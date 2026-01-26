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

Log.debug("Loading modules...")

-- local Commands = require("@server/commands")
local WorkerManagers = require("@shared/workerManagers")
local Protection = require("@shared/protection")

WorkerManagers:Init(root, "workerManager")
-- Network:Init()
-- Commands:Init({ require("@server/commands/default"), require("@server/commands/get") })

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

WorkerManagers:ready()

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)

local ScriptManager = require("@server/scriptManager")

local player = nil

do
	local Players = game:GetService("Players")

	repeat
		player = Players:FindFirstChildOfClass("Player")
		task.wait()
	until player

	local testScript = ScriptManager:CreateScript(
		player,
		require("@shared/scriptManager/scriptTypes").Script,
		"TestRunner",
		(game:WaitForChild("testRunnerSource") :: StringValue).Value
	)
	testScript.Enabled = true

	Log.print("Running test script...")
	testScript.Parent = workspace
end

return nil
