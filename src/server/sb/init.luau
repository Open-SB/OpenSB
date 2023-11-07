local __start = os.clock()

-- Localize variables and remove environment for security
local game = game
local task = task
local script = script
local setfenv = setfenv
local os = os
local math = math
local coroutine = coroutine
local ipairs = ipairs

-- We bundle all modules into one script, which all get inlined above this one. So we only need to remove the environment here.
setfenv(1, {})

-- Fetch assets and destroy script
local Log = require("shared/log")
Log.debug("Fetching assets")

local sbActor = script.Parent
local clientScripts = script:WaitForChild("clientScripts"):Clone()

do
	local attributeChanged = sbActor:GetAttributeChangedSignal("canDestroy")
	while not sbActor:GetAttribute("canDestroy") do
		attributeChanged:Wait()
	end
end

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			sbActor:Destroy()
			script:Destroy()
			script = nil

			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

-- Services and modules
local Players = game:GetService("Players")

Log.debug("Loading modules")

local Network = require("server/network")
local Chat = require("server/chat")
local Functions = require("shared/functions")

Network:Init()
Chat:Init()

Log.debug("Loading systems") -- Maybe we should move these into their own modules?

-- Player system
do
	local function disconnectPlayer() end

	local function connectPlayer(player: Player)
		Log.debug("Checking if " .. player.Name .. " can join...") -- TODO: String interpolation

		if not _G.DEV and player.AccountAge < 7 then
			Log.debug(player.Name .. "'s account age is too young (<7).") -- TODO: String interpolation
			player:Kick("Your account age has to be atleast one week old to play this game.")

			-- TODO: Alert to others why they couldnt join

			return
		end

		Log.debug("Checking ban on " .. player.Name .. "...") -- TODO: String interpolation
		-- TODO: Ban check

		do
			Log.debug("Loading SB client on " .. player.Name .. "...") -- TODO: String interpolation

			local playerGui = player:FindFirstChildOfClass("PlayerGui")
			if not playerGui then
				Log.debug(player .. " had no player gui.") -- TODO: String interpolation
				player:Kick("PlayerGui was not found while loading.")

				return
			end

			local screenGui = clientScripts:Clone()
			screenGui.Name = Functions.randomInstanceName()
			screenGui.Archivable = false

			local sbClientActor = screenGui:WaitForChild("sbActor")
			sbClientActor.Archivable = false

			local sbClient = sbClientActor:WaitForChild("sb")
			sbClient.Name = Functions.randomInstanceName()
			sbClient.Archivable = false

			local sandboxClient = screenGui:WaitForChild("sandbox")
			sandboxClient.Name = Functions.randomInstanceName()
			sandboxClient.Archivable = false

			-- Tranfer the remote attribute to find the remote
			sbClient:SetAttribute(Network.attributeName, Network.attributeValue)

			screenGui.Parent = playerGui
			task.delay(1, function()
				screenGui:Destroy()
				sbClientActor:Destroy()
				sbClient:Destroy()
				sandboxClient:Destroy()
			end)
		end
	end

	Players.PlayerAdded:Connect(connectPlayer)
	Players.PlayerRemoving:Connect(disconnectPlayer)

	for _, player: Player in ipairs(Players:GetPlayers()) do
		task.spawn(connectPlayer, player)
	end
end

-- Finalize
Log.debug("Finalizing...")

Players.CharacterAutoLoads = true
for _, player: Player in ipairs(Players:GetPlayers()) do
	task.defer(player.LoadCharacter, player)
end

Log.print("Loaded in " .. math.round((os.clock() - __start) * 1000) .. "ms.") -- TODO: String interpolation

return nil
