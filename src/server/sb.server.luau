local __start = os.clock()

local Log = require("shared/log")
Log.print("Loading...")

-- Fetch assets and destroy script
local sbActor = script.Parent
local root = sbActor.Parent

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

local Assets = require("shared/assets")
Assets:Init(root, "assets")

local clientScripts = Assets:get("clientScripts")
local clientAssets = clientScripts:WaitForChild("assets")
clientAssets:SetAttribute("_descendants", #clientAssets:GetDescendants())

-- Services and modules
local Players = game:GetService("Players")

Log.debug("Loading modules...")

local Network = require("server/network")
local Commands = require("server/commands")
local Output = require("server/output")
local Chat = require("server/chat")
local World = require("server/world")
local Functions = require("shared/functions")

Network:Init()
Chat:Init()
Commands:Init()

Log.debug("Loading systems...") -- Maybe we should move these into their own modules?

-- Player system
do
	local function disconnectPlayer() end

	local function connectPlayer(player: Player)
		Log.debug(`Checking if {player.Name} can join...`)

		if not _G.DEV and player.AccountAge < 7 then
			Log.debug(`{player.Name}'s account age is too young (<7).`)
			player:Kick("Your account needs to be atleast one week old to play this game.")

			Output:appendToOthers(
				player,
				Output.MessageType.Success,
				`{player.Name} was kicked due to their account not being older than one week.`
			)

			return
		end

		Log.debug(`Checking ban on {player.Name}...`)
		-- TODO: Ban check

		Output:appendToOthers(player, Output.MessageType.Success, `{player.Name} has joined the server.`)

		do
			Log.debug(`Loading SB client on {player.Name}...`)

			local playerGui = player:FindFirstChildOfClass("PlayerGui")
			if not playerGui then
				Log.debug(`{player.Name} had no player gui.`)
				player:Kick("PlayerGui was not found while loading.")

				return
			end

			local screenGui = clientScripts:Clone()
			screenGui.Name = Functions.randomInstanceName()
			screenGui.Archivable = false

			local sbClientActor = screenGui:WaitForChild("sbActor")
			sbClientActor.Name = Functions.randomInstanceName()
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
			task.delay(10, function()
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

World:Init()
Players.CharacterAutoLoads = true
for _, player: Player in ipairs(Players:GetPlayers()) do
	task.defer(player.LoadCharacter, player)
end

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)

return nil
