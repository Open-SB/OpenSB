local __start = os.clock()

local Log = require("@shared/log")
Log:SetPrefix("[SB]")
Log.print("Loading...")

do
	local wm = require("@shared/wm")
	wm.isWorkerManager = false
	table.freeze(wm)
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

local Assets = require("@shared/assets")
Assets:Init(root, "assets")

local clientScripts = Assets:get("clientScripts")
do
	local clientAssets = clientScripts:WaitForChild("assets")
	clientAssets:SetAttribute("_descendants", #clientAssets:GetDescendants())
end

-- Services and modules
local Players = game:GetService("Players")

Log.debug("Loading modules...")

local Network = require("@server/network")
local Commands = require("@server/commands")
local Output = require("@server/output")
local World = require("@server/world")
local WorkerManagers = require("@shared/workerManagers")
local Functions = require("@shared/functions")
local Protection = require("@shared/protection")

WorkerManagers:Init(root, "workerManager")
Network:Init()
Commands:Init({ require("@server/commands/default"), require("@server/commands/get") })

Log.debug("Loading systems...") -- Maybe we should move these into their own modules?

-- Player system
do
	local PlayerList = require("@shared/playerList")

	local function disconnectPlayer(player: Player)
		Output:appendToOthers(
			player,
			Output.MessageType.Success,
			`{Functions.formatPlayerName(player)} has left the server.`
		)
	end

	local function connectPlayer(player: Player)
		Log.debug(`Checking if {player.Name} can join...`)

		if _G.accountAgeLimit > 0 and player.AccountAge < _G.accountAgeLimit then
			Log.debug(`{player.Name}'s account age is too young (<{_G.accountAgeLimit} days).`)
			player:Kick(`Your account needs to be atleast {_G.accountAgeLimit} days old to play this game.`)

			Output:appendToOthers(
				player,
				Output.MessageType.Success,
				`{Functions.formatPlayerName(player)} was kicked due to their account not being older than one week.`
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

	PlayerList.Added:Connect(connectPlayer)
	PlayerList.Removed:Connect(disconnectPlayer)

	for _, player: Player in ipairs(PlayerList:GetList()) do
		task.spawn(connectPlayer, player)
	end
end

task.spawn(function()
	Log.debug("Protecting TextChatService...")

	local TextChatService = game:GetService("TextChatService")

	local function protectWithExpectedStructure(instance: Instance, structure: { [string]: any })
		for name, subStructure in structure do
			local child = instance:WaitForChild(name)
			Protection.add(child, "write")

			protectWithExpectedStructure(child, subStructure)
		end
	end

	Protection.add(TextChatService, "write")
	protectWithExpectedStructure(TextChatService, {
		ChatWindowConfiguration = {},
		TextChannels = {
			RBXGeneral = {},
			RBXSystem = {},
		},
		TextChatCommands = {
			RBXHelpCommand = {},
			RBXUnmuteCommand = {},
			RBXTeamCommand = {},
			RBXClearCommand = {},
			RBXEmoteCommand = {},
			RBXWhisperCommand = {},
			RBXMuteCommand = {},
			RBXVersionCommand = {},
			RBXConsoleCommand = {},
		},
		ChatInputBarConfiguration = {},
		ChannelTabsConfiguration = {},
		BubbleChatConfiguration = {},
	})

	Log.debug("TextChatService should be fully protected")
end)

-- Finalize
Log.debug("Finalizing...")

World:Init()
Players.CharacterAutoLoads = true
for _, player: Player in ipairs(Players:GetPlayers()) do
	task.defer(player.LoadCharacter, player)
end

WorkerManagers:ready()
Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)

return nil
