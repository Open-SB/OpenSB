local __start = os.clock()

-- Localize variables and remove environment for security
local game = game
local coroutine = coroutine
local task = task
local script = script
local setfenv = setfenv
local math = math
local os = os
local next = next

-- We bundle all modules into one script, which all get inlined above this one. So we only need to remove the environment here.
setfenv(1, {})

local networkAttribute = { next(script:GetAttributes()) }

-- Fetch assets and destroy script
local Log = require("shared/log")
Log.debug("Fetching assets")

local sbActor = script.Parent

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
Log.debug("Loading modules")

local Network = require("client/network")
local Chat = require("client/chat")
local StarterScripts = require("client/starterScripts")

Network:Init(networkAttribute)
Chat:Init()
StarterScripts:Init()

-- Finalize
Log.debug("Finalizing...")
Log.print("Loaded in " .. math.round((os.clock() - __start) * 1000) .. "ms") -- TODO: String interpolation

return nil
