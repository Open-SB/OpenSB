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
local ipairs = ipairs

local Sandbox = require("server/wm/sandbox")
local Wrapper = require("server/wm/sandbox/wrapper")
local ManagerCommunication = require("shared/wm/communication")

local compile = require("server/compile")
local Functions = require("shared/functions")
local ScriptTypes = require("shared/scriptManager/scriptTypes")

local CollectionService = game:GetService("CollectionService")

type source = {
	owner: Player,
	error: string?,
	source: string?,
	bytecode: buffer?,
	arguments: { n: number } & { any },
	isWorker: boolean?,
	compiling: boolean?,
}

local sources: { [any]: { [string]: source } } = {
	[ScriptTypes.Script] = {},
	[ScriptTypes.LocalScript] = {},
	[ScriptTypes.ModuleScript] = {},
}
local scripts = {}

local Module = {}

function Module:Init()
	ManagerCommunication:onInvoke("fetchSource", function(player: Player, scriptType, sourceId: string)
		local classSources = sources[scriptType]
		if not classSources then
			return
		end

		local data = classSources[sourceId]
		if not data then
			return
		end

		-- TODO: Check if the player can run the script

		-- Compile source to bytecode if not done already
		if not data.bytecode and not data.error and not data.compiling then
			if not data.source then
				-- Cannot compile without source
				return
			end

			data.compiling = true

			local success, result = compile(data.source)
			if not success then
				data.error = result
			else
				data.bytecode = result
			end

			data.compiling = false
		elseif not data.error then
			repeat
				-- Wait for script to finish compiling
				task.wait()
			until not data.compiling
		end

		if data.error then
			return {
				owner = data.owner,
				error = data.error,
			}
		end

		return {
			owner = data.owner,
			bytecode = data.bytecode,
			arguments = data.arguments,
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
				end)
			end

			local id = Functions.randomString(16)
			sources[scriptType][id] = data
			return id
		end
	)

	ManagerCommunication:on("NewWorker", function(owner: Player, source: string, host: ModuleScript, arguments: table?)
		local id = Functions.randomString(16)
		sources[ScriptTypes.ModuleScript][id] = {
			owner = owner,
			source = source,
			arguments = table.freeze(if arguments then arguments else table.pack()),
			isWorker = true,
		}

		-- We need an actual host for workers for error catching to work correctly and due to how we track sandboxes (getfenv(0))
		-- We use a modulescript because it allows us to start the script under our actor while the actor is destroyed
		-- Only downside to this is that it will cost a little extra memory for each worker (due to them having their own ModuleScript)
		host.Parent = Instance.new("Actor")
		host:SetAttribute("__sb_source", id)
		host:AddTag("__sb_script")

		task.defer(require, host)
	end)

	-- TODO: Tell client to stop LocalScript (maybe?).
	ManagerCommunication:on("stopScript", function(script: BaseScript)
		local scriptData = scripts[script]
		if scriptData then
			scripts[script] = nil
			Sandbox.terminate(scriptData.sandbox, true)
		end

		Sandbox.kill(script)
	end)

	ManagerCommunication:on("stopScripts", function(player: Player?, stopServerScripts: boolean, removeType)
		local kill = {}
		for _, script in ipairs(CollectionService:GetTagged("__sb_script")) do
			local sourceId = script:GetAttribute("__sb_source")
			if not sourceId then
				continue
			end

			local className = script.ClassName
			local scriptType = if className == "Script"
				then ScriptTypes.Script
				elseif className == "LocalScript" then ScriptTypes.LocalScript
				else ScriptTypes.ModuleScript

			local source = sources[scriptType][sourceId]
			if not source then
				continue
			end

			if player and source.owner.UserId ~= player.UserId then
				continue
			end

			if not removeType or removeType == scriptType then
				table.insert(kill, script)
			end
		end

		for type, list in sources do
			if removeType and removeType ~= type then
				continue
			end

			for id, source in ipairs(list) do
				if player and source.owner.UserId ~= player.UserId then
					continue
				end

				list[id] = nil
			end
		end

		if stopServerScripts then
			for script, data in scripts do
				if player and data.sandbox.Owner.UserId ~= player.UserId then
					continue
				end

				Sandbox.terminate(data.sandbox, true)
				scripts[script] = nil
			end
		end

		for _, script in ipairs(kill) do
			Sandbox.kill(script)
		end
	end)

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

			if not hostScript:HasTag("__sb_script") then
				return error("invalid script", 2)
			end

			local sourceId = hostScript:GetAttribute("__sb_source")
			if not sourceId then
				return error("invalid script", 2)
			end

			local scriptType = if className == "Script" then ScriptTypes.Script else ScriptTypes.ModuleScript
			local sourceData = sources[scriptType][sourceId]
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
			scripts[hostScript] = table.freeze({ sandbox = sandbox, source = sourceData, type = scriptType })

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
		local scriptData = scripts[script]
		if not scriptData then
			return
		end

		local player = scriptData.sandbox.Owner
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
