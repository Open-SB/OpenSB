local table = table
local task = task
local pcall = pcall
local error = error
local getfenv = getfenv
local debug = debug
local setmetatable = setmetatable
local rawset = rawset
local _G = _G
local shared = shared

local Log = require("shared/log")
local Environment = require("./environment")
local Wrapper = require("./wrapper")

local envLookup = {}
local scriptLookup = {}

local wrapMap = {} :: { [any]: any } -- Maps things to their wrapped version (custom unlike Wrapper.wrap)
local unwrapMap = {} :: { [any]: any } -- Maps things to their unwrapped version (custom unlike Wrapper.unwrap)

do
	setmetatable(wrapMap, {
		__metatable = "The metatable is locked",
		__newindex = function(_, unwrapped, wrapped)
			if wrapMap[unwrapped] then
				return
			end

			rawset(wrapMap, unwrapped, wrapped)
			rawset(unwrapMap, wrapped, unwrapped)
		end,
	})

	setmetatable(unwrapMap, {
		__metatable = "The metatable is locked",
		__newindex = function(_, wrapped, unwrapped)
			if unwrapMap[wrapped] then
				return
			end

			rawset(wrapMap, unwrapped, wrapped)
			rawset(unwrapMap, wrapped, unwrapped)
		end,
	})
end

-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#_G
local __G = setmetatable({}, { __metatable = "The metatable is locked" })
wrapMap[_G] = __G

-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#shared
local _shared = setmetatable({}, { __metatable = "The metatable is locked" })
wrapMap[shared] = _shared

local Module = {}
Module.WrapMap = wrapMap
Module.UnwrapMap = unwrapMap

export type sandbox = {
	Terminated: boolean,
	Script: BaseScript?,
	Owner: Player,
	Environment: table,
	Connections: { [RBXScriptConnection]: true },
	Threads: { [thread]: true },
	Environments: { table },
}

function Module.new(owner: Player, script: BaseScript?): sandbox
	local environment = Environment.new({
		script = script,
		owner = owner,

		-- For some reason Roblox moved these out of the "environment globals" and instead into the "script globals" or whatever (check print(getfenv()))
		_G = __G,
		shared = _shared,
	})

	local sandbox = {}
	sandbox.Terminated = false
	sandbox.Script = script
	sandbox.Owner = owner
	sandbox.Environment = environment
	sandbox.Connections = {}
	sandbox.Threads = {}
	sandbox.Environments = { environment }

	envLookup[environment] = sandbox
	if script then
		scriptLookup[script] = sandbox
	end

	return sandbox
end

function Module.getSandbox(): sandbox?
	local success, env = pcall(getfenv, 0)
	if success then
		local sandbox = envLookup[env]
		if sandbox then
			return sandbox
		end
	end

	-- If we cannot get the sandbox, it's probably best to throw an error
	error("failed to get sandbox", 0)
end

-- Calling it "assertTerminated" may make it sound like we error if it's NOT terminated (i.e something like "refuseTerminated" or "assertRunning" would be better).
function Module.assertTerminated(sandbox: sandbox?)
	if (sandbox or Module.getSandbox()).Terminated then
		-- We use task.delay to schedule termination instead of task.defer because defer may throw an error if it exceeds the limit of 80
		task.delay(0, Module.Terminate, Module, sandbox)
		error("sandbox terminated", 0)
	end
end

function Module.claimEnvironment(environment: table, sandbox: sandbox?)
	sandbox = sandbox or Module.getSandbox()
	Module.assertTerminated(sandbox)

	sandbox.Environments[environment] = true
	envLookup[environment] = sandbox
end

function Module.getSandboxFromFunction(func: () -> ()): sandbox?
	local l, s = debug.info(func, "ls")
	if l == -1 and s == "[C]" then
		-- Using getfenv() on C functions will return the current environment
		return
	end

	return envLookup[getfenv(func)]
end

function Module:Terminate(sandbox: sandbox)
	sandbox.Terminated = true

	local connections = sandbox.Connections
	for connection, _ in connections do
		if pcall(connection.Disconnect, connection) then
			connections[connection] = nil
		end
	end

	local threads = sandbox.Threads
	for thread, _ in threads do
		if pcall(task.cancel, thread) then
			threads[thread] = nil
		end
	end

	local environments = sandbox.Environments
	for environment, _ in environments do
		envLookup[environment] = nil

		table.clear(environment)
		pcall(function()
			setmetatable(environment, nil)
			table.freeze(environment)
		end)

		environments[environment] = nil
	end

	local script = sandbox.Script
	if not script then
		return
	end

	scriptLookup[script] = nil

	pcall(function()
		script:Destroy()
		script.Enabled = false
	end)
end

function Module:Init()
	Log.debug("Initializing sandbox...")

	Wrapper.setSandbox(Module)
	Environment.setSandbox(Module)
	Environment:Init()
end

return table.freeze(Module)
