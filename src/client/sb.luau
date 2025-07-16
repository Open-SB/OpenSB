local __start = os.clock()
local networkAttribute = { next(script:GetAttributes()) }

local Log = require("@shared/log")
Log:SetPrefix("[SB Client]")
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

-- Services and modules
Log.debug("Loading modules...")

local Network = require("@client/network")
local Commands = require("@client/commands")
local UI = require("@client/ui")
local StarterScripts = require("@client/starterScripts")
local Output = require("@client/output")
local WorkerManagers = require("@shared/workerManagers")

WorkerManagers:Init(root, "localWorkerManager")
require("@client/scriptManager")
Network:Init(networkAttribute)
Commands:Init({ require("@client/commands/default"), require("@client/commands/get") })
UI:Init()
StarterScripts:Init()

-- Finalize
Log.debug("Finalizing...")

WorkerManagers:ready()

local loadTime = math.round((os.clock() - __start) * 1000)
Log.print(`Loaded in {loadTime}ms.`)

task.defer(function()
	-- Make sure UI is loaded.
	UI:WaitUntilLoaded()

	local buildType = if _G.dev then "development" else "production"
	Output:append(Output.MessageType.System, `OpenSB {buildType} build. Ran in {loadTime}ms.`)
end)

return nil
