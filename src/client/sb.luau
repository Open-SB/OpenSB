local __start = os.clock()
local networkAttribute = { next(script:GetAttributes()) }

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

-- Services and modules
Log.debug("Loading modules...")

local Network = require("client/network")
local Commands = require("client/commands")
local Chat = require("client/chat")
local StarterScripts = require("client/starterScripts")

Network:Init(networkAttribute)
Chat:Init()
Commands:Init()
StarterScripts:Init()

-- Finalize
Log.debug("Finalizing...")
Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms`)

return nil
