local game = game
local setmetatable = setmetatable

local Log = require("shared/log")
local Environment = require("./environment")
local VM = require("./vm")

local Players = game:GetService("Players")

local localPlayer = Players.LocalPlayer

local envLookup = {}
local scriptLookup = {}

local closureInfo = VM.closureInfo
local functionMap = {} :: { [() -> ()]: () -> () } -- Maps functions to their sandboxed version (used to replace functions upon calling)
local reverseFunctionMap = {} :: { [() -> ()]: () -> () } -- Reverse of above

do
	setmetatable(functionMap, {
		__metatable = "The metatable is locked",
		__newindex = function(_, unwrapped, wrapped)
			if functionMap[unwrapped] then
				return
			end

			rawset(functionMap, unwrapped, wrapped)
			rawset(reverseFunctionMap, wrapped, unwrapped)
		end,
	})

	setmetatable(reverseFunctionMap, {
		__metatable = "The metatable is locked",
		__newindex = function(_, wrapped, unwrapped)
			if reverseFunctionMap[wrapped] then
				return
			end

			rawset(functionMap, unwrapped, wrapped)
			rawset(reverseFunctionMap, wrapped, unwrapped)
		end,
	})
end

-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#_G
local __G = setmetatable({}, { __metatable = "The metatable is locked" })

-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#shared
local _shared = setmetatable({}, { __metatable = "The metatable is locked" })

local Module = {}
Module.FunctionMap = functionMap
Module.ReverseFunctionMap = reverseFunctionMap

export type sandbox = {
	Terminated: boolean,
	Terminator: () -> ()?,
	Script: BaseScript?,
	Owner: Player,
	ClientSideOnly: boolean,
	StackSource: string?,
	Environment: table,
	Connections: { [RBXScriptConnection]: true },
	Threads: { [thread]: true },
	Environments: { [table]: true },
}

function Module.new(owner: Player, bytecode: buffer, script: BaseScript?): sandbox
	local environment = Environment.new({
		script = script,
		owner = localPlayer,

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
	sandbox.Environments = { [environment] = true }

	envLookup[environment] = sandbox
	if script then
		scriptLookup[script] = sandbox
	end

	local main, luau_close = VM.luau_load(bytecode, sandbox)
	sandbox.Terminator = luau_close

	return sandbox, main
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

function Module.claimEnvironment(environment: table, sandbox: sandbox?)
	sandbox = sandbox or Module.getSandbox()
	Module.assertTerminated(sandbox)

	sandbox.Environments[environment] = true
	envLookup[environment] = sandbox
end

function Module.getSandboxFromFunction(func: () -> ()): sandbox?
	return closureInfo[func]
end

function Module.terminate(sandbox: sandbox, keepScript: boolean?)
	sandbox.Terminated = true
	if sandbox.Terminator then
		sandbox.Terminator()
	end

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

	if keepScript then
		return
	end

	pcall(function()
		script:Destroy()
		script.Enabled = false
	end)
end

function Module:Init()
	Log.debug("Initializing sandbox...")

	VM.setSandbox(Module)
	Environment.setSandbox(Module)
	Environment:Init()
end

return Module
