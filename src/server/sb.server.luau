local __start = os.clock()

local Log = require("shared/log")
Log:SetPrefix("[SB]")
Log.print("Loading...")

if not _G.DEV and _G.scriptHostKey == "CHANGE_THIS_KEY" then
	Log.warn(
		"The 'scriptHostKey' global is set to the default value while in a production build! Consider changing it."
	)
end

if not _G.DEV and _G.localScriptHostKey == "CHANGE_THIS_KEY" then
	Log.warn(
		"The 'localScriptHostKey' global is set to the default value while in a production build! Consider changing it."
	)
end

if not _G.DEV and _G.moduleScriptHostKey == "CHANGE_THIS_KEY" then
	Log.warn(
		"The 'moduleScriptHostKey' global is set to the default value while in a production build! Consider changing it."
	)
end

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

			task.spawn(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

local Assets = require("shared/assets")
Assets:Init(root, "assets")

local clientScripts = Assets:get("clientScripts")
do
	local clientAssets = clientScripts:WaitForChild("assets")
	clientAssets:SetAttribute("_descendants", #clientAssets:GetDescendants())
end

-- Services and modules
local Players = game:GetService("Players")

Log.debug("Loading modules...")

local Network = require("server/network")
local Commands = require("server/commands")
local Output = require("server/output")
local Chat = require("server/chat")
local World = require("server/world")
local WorkerManagers = require("shared/workerManagers")
local Functions = require("shared/functions")

WorkerManagers:Init(root, "workerManager")
Network:Init()
Chat:Init()
Commands:Init({ require("server/commands/default"), require("server/commands/get") })

Log.debug("Loading systems...") -- Maybe we should move these into their own modules?

-- Player system
do
	local function disconnectPlayer(player: Player)
		Output:appendToOthers(
			player,
			Output.MessageType.Success,
			`{Functions.formatPlayerName(player)} left the server.`
		)
	end

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

		Output:appendToOthers(
			player,
			Output.MessageType.Success,
			`{Functions.formatPlayerName(player)} has joined the server.`
		)

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

			local clientWorkerManager = screenGui:WaitForChild("localWorkerManager")
			local clientAssets = screenGui:WaitForChild("assets")

			-- Tranfer the remote attribute to find the remote
			sbClient:SetAttribute(Network.attributeName, Network.attributeValue)

			screenGui.Parent = playerGui
			task.delay(10, function()
				screenGui:Destroy()
				sbClientActor:Destroy()
				sbClient:Destroy()
				clientWorkerManager:Destroy()
				clientAssets:Destroy()
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
