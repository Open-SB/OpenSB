local __start = os.clock()

local setfenv = setfenv
local script = script
local coroutine = coroutine
local task = task
local setmetatable = setmetatable
local shared = shared
local rawequal = rawequal
local error = error
local loadstring = loadstring
local unpack = unpack
local math = math
local tostring = tostring
local typeof = typeof
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
			local parent = script.Parent
			script:Destroy()
			script = nil

			if parent.ClassName == "Actor" then
				parent:Destroy()
			end

			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

local ManagerCommunication = require("shared/wm/communication")
ManagerCommunication:init(unpack(communicationBindables))

local ScriptTypes = require("server/scriptManager/scriptTypes")
local Functions = require("shared/functions")

local sources = {
	[ScriptTypes.Script] = {} :: { [string]: string },
	[ScriptTypes.LocalScript] = {} :: { [string]: string },
	[ScriptTypes.ModuleScript] = {} :: { [string]: string },
}

ManagerCommunication:onInvoke("CreateSourceId", function(owner, scriptType, source, name)
	local id = Functions.randomString(16)
	sources[scriptType][id] = source

	return id
end)

setmetatable(shared, {
	__metatable = "The metatable is locked",
	__call = function(_, key, hostScript)
		-- Use rawequal to bypass potential __eq metamethods
		if rawequal(key, _G.scriptHostKey) then
			if typeof(hostScript) ~= "Instance" or hostScript.ClassName ~= "Script" then
				return error("invalid script", 2)
			end
		elseif rawequal(key, _G.moduleScriptHostKey) then
			if typeof(hostScript) ~= "Instance" or hostScript.ClassName ~= "ModuleScript" then
				return error("invalid script", 2)
			end
		else
			return error("invalid key", 2)
		end

		local sourceId = hostScript:GetAttribute("source")
		if not sourceId then
			return error("invalid script", 2)
		end

		local source = if hostScript.ClassName == "Script"
			then sources[ScriptTypes.Script][sourceId]
			else sources[ScriptTypes.ModuleScript][sourceId]
		if not source then
			return error("invalid script", 2)
		end

		local func, err = loadstring(source, "=" .. hostScript:GetFullName()) -- Prefixing with a "=" removes the [string ""] from the chunkname.
		if not func then
			return nil, err
		end

		return func
	end,
})

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)
