local __start = os.clock()

local setfenv = setfenv
local script = script
local coroutine = coroutine
local task = task
local setmetatable = setmetatable
local shared = shared
local rawequal = rawequal
local error = error
local unpack = unpack
local math = math
local tostring = tostring
local os = os

local Log = require("shared/log")
Log:SetPrefix("[" .. script.Name .. "]")
Log.print("Loading...")

local communicationBindables = { script:FindFirstChildOfClass("BindableFunction"):Invoke() }

-- Preload all darklua modules this script requires, so they can initialize all global variables they will use into local ones (because we clear the env).
do
	Log.debug("Preloading modules...")

	-- selene: allow(undefined_variable)
	local modules = __DARKLUA_BUNDLE_MODULES -- Check .darklua.json
	for name, _ in modules do
		if name ~= "cache" and name ~= "load" then -- darklua places all modules, the load function, and cache table in the same table (we don't want to call cache and load).
			modules.load(name)
		end
	end
end

setfenv(1, {})

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			script:Destroy()
			script = nil

			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

local ManagerCommunication = require("shared/workerManagers/communication")
ManagerCommunication:init(unpack(communicationBindables))

setmetatable(shared, {
	__metatable = "The metatable is locked",
	__call = function(_, key, hostScript)
		if not rawequal(key, _G.localScriptHostKey) then -- Use rawequal to bypass potential __eq metamethods
			return error("invalid key", 2)
		end

		return function() end
	end,
})

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)
