--!strict
local __start = os.clock()

-- Localize variables and remove environment for security
local game = game
local task = task
local script = script
local setfenv = setfenv
local os = os
local math = math
local Instance = Instance
local coroutine = coroutine
local ipairs = ipairs
local require = require

-- These are replaced later
local _print = print
local _warn = warn

setfenv(1, {})

local Log = require(script:WaitForChild("modules"):WaitForChild("log"))[1]

-- Fetch assets and destroy script
Log.debug("Fetching assets")

local sbActor = script.Parent

local modules = script:WaitForChild("modules"):Clone()
local clientScripts = script:WaitForChild("clientScripts"):Clone()
do
	local sbClient = clientScripts:WaitForChild("sbActor"):WaitForChild("sb")
	sbClient:SetAttribute("_descendants", #sbClient:GetDescendants()) -- We set this to tell the client how many descendants it should expect before destroying itself
end

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
local RunService = game:GetService("RunService")

Log.debug("Loading modules")

local Modules = require(modules)
local Network = Modules.require("network")
local Functions = Modules.require("functions")

Log.debug("Loading systems") -- Maybe we should move these into their own modules?

-- Player system
do
	local function disconnectPlayer() end

	local function connectPlayer(player: Player)
		Log.debug(`Checking if {player} can join...`)

		if not RunService:IsStudio() and player.AccountAge < 7 then
			Log.debug(`{player}'s account age is too young (<7).`)
			player:Kick(`Your account age has to be atleast one week old to play this game.`)

			-- TODO: Alert to others why they couldnt join

			return
		end

		Log.debug(`Checking ban on {player}...`)
		-- TODO: Ban check

		do
			Log.debug(`Loading SB client on {player}...`)

			local playerGui = player:FindFirstChildOfClass("PlayerGui")
			if not playerGui then
				Log.debug(`{player} had no player gui.`)
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

Modules.waitForModulesToLoad()
Modules:Lock()
modules:Destroy()

Players.CharacterAutoLoads = true
for _, player: Player in ipairs(Players:GetPlayers()) do
	player:LoadCharacter()
end

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)
