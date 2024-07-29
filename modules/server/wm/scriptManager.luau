local setmetatable = setmetatable
local shared = shared
local typeof = typeof
local error = error
local pcall = pcall
local rawequal = rawequal
local loadstring = loadstring
local getfenv = getfenv
local coroutine = coroutine
local game = game
local debug = debug
local string = string
local task = task
local table = table

local Sandbox = require("server/wm/sandbox")
local Wrapper = require("server/wm/sandbox/wrapper")
local ManagerCommunication = require("shared/wm/communication")

local compile = require("server/compile")
local Functions = require("shared/functions")
local ScriptTypes = require("shared/scriptManager/scriptTypes")

type source = {
	owner: Player,
	error: string?,
	source: string?,
	bytecode: string?,
	arguments: { n: number } & { any },
	isWorker: boolean?,
	compiling: boolean?,
}

local sources = {
	[ScriptTypes.Script] = {} :: { [string]: source },
	[ScriptTypes.LocalScript] = {} :: { [string]: source },
	[ScriptTypes.ModuleScript] = {} :: { [string]: source },
}
local scripts = {}

local Module = {}

function Module:Init()
	ManagerCommunication:onInvoke("fetchSource", function(player: Player, scriptType, sourceId: string)
		local classSources = sources[scriptType]
		if not classSources then
			return
		end

		local sourceData = classSources[sourceId]
		if not sourceData then
			return
		end

		-- TODO: Compile modules if not already
		-- TODO: Check if the player can run the script

		while sourceData.compiling do
			-- Wait for script to finish compiling if it hasn't already
			task.wait()
		end

		return {
			owner = sourceData.owner,
			error = sourceData.error,
			bytecode = sourceData.bytecode,
			arguments = sourceData.arguments,
		}
	end)

	ManagerCommunication:onInvoke(
		"CreateSourceId",
		function(owner: Player, scriptType, source: string, arguments: BindableFunction?)
			local data = {
				owner = owner,
				arguments = table.freeze(if arguments then table.pack(arguments:Invoke()) else table.pack()),
			}

			if scriptType ~= ScriptTypes.LocalScript then
				data.source = source
				table.freeze(data)
			else
				data.compiling = true

				task.spawn(function() -- compile() yields
					local success, result = compile(source)
					if not success then
						data.error = result
					else
						data.bytecode = result
					end

					data.compiling = false
					table.freeze(data)
				end)
			end

			local id = Functions.randomString(16)
			sources[scriptType][id] = data
			return id
		end
	)

	ManagerCommunication:on(
		"NewWorker",
		function(owner: Player, source: string, host: ModuleScript, arguments: BindableFunction?)
			local id = Functions.randomString(16)
			sources[ScriptTypes.ModuleScript][id] = table.freeze({
				owner = owner,
				source = source,
				arguments = table.freeze(if arguments then table.pack(arguments:Invoke()) else table.pack()),
				isWorker = true,
			})

			-- We need an actual host for workers for error catching to work correctly and due to how we track sandboxes (getfenv(0))
			-- We use a modulescript because it allows us to start the script under our actor while the actor is destroyed
			-- Only downside to this is that it will cost a little extra memory for each worker (due to them having their own ModuleScript)
			host.Parent = Instance.new("Actor")
			host:SetAttribute("source", id)
			task.defer(require, host)
		end
	)

	setmetatable(_G, { __metatable = "The metatable is locked" })
	setmetatable(shared, {
		__metatable = "The metatable is locked",
		__call = function(_, key, hostScript)
			if typeof(hostScript) ~= "Instance" then
				return error("invalid script", 2)
			end

			-- Pcall while obtaining the ClassName prevents any RobloxLocked instance from throwing an error here
			local className: string?
			pcall(function()
				className = hostScript.ClassName
			end)

			-- Use rawequal to bypass potential __eq metamethods
			if className == "Script" then
				if not rawequal(key, _G.scriptHostKey) then
					return error("invalid key", 2)
				end
			elseif className == "ModuleScript" then
				if not rawequal(key, _G.moduleScriptHostKey) then
					return error("invalid key", 2)
				end
			else
				return error("invalid script", 2)
			end

			local sourceId = hostScript:GetAttribute("source")
			if not sourceId then
				return error("invalid script", 2)
			end

			local sourceData = if className == "Script"
				then sources[ScriptTypes.Script][sourceId]
				else sources[ScriptTypes.ModuleScript][sourceId]
			if not sourceData then
				return error("invalid script", 2)
			end

			local func, err = loadstring(sourceData.source, "=" .. hostScript:GetFullName()) -- Prefixing with a "=" removes the [string ""] from the chunkname
			if not func then
				ManagerCommunication:Send("error", sourceData.owner, err)
				return nil, nil, nil, err
			end

			local sandbox, sandboxedFunc =
				Sandbox.new(sourceData.owner, func, if not sourceData.isWorker then hostScript else nil)
			scripts[hostScript] = sandbox

			-- Track the calling thread (this thread)
			sandbox.Threads[coroutine.running()] = true

			return sandboxedFunc,
				table.pack(Wrapper.wrapMany(unpack(sourceData.arguments, 1, sourceData.arguments.n))), -- We don't want to wrap a table, just the arguments
				if className == "Script" or sourceData.isWorker
					then function(thread)
						sandbox.Threads[thread] = true
					end
					else function(...)
						return Wrapper.unwrapMany(...)
					end
		end,
	})

	-- Get the source of the worker manager (to filter out stack traces)
	local wmSource = debug.info(Functions.empty, "s")

	-- Listen for script errors
	game:GetService("ScriptContext").Error:Connect(function(message, stackTrace, script)
		local sandbox = scripts[script]
		if not sandbox then
			return
		end

		local player = sandbox.Owner
		ManagerCommunication:Send("error", player, message)
		ManagerCommunication:Send("info", player, "Stack Begin")

		-- Format and filter out sb stack traces
		local traces = string.split(stackTrace, "\n")
		for index = 1, #traces - 1 do -- Last trace is always "" (so we skip it)
			local source, line, func = string.match(traces[index], "^(.+), line (%d+) %- function (.+)$")
			if not func then
				source, line = string.match(traces[index], "^(.+), line (%d+)$")
			end

			if source == wmSource then
				continue
			end

			if func then
				ManagerCommunication:Send("info", player, `Script '{source}', Line {line} - function {func}`)
			else
				ManagerCommunication:Send("info", player, `Script '{source}', Line {line}`)
			end
		end

		ManagerCommunication:Send("info", player, "Stack End")
	end)
end

return Module
