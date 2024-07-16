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

local Sandbox = require("server/wm/sandbox")
local Wrapper = require("server/wm/sandbox/wrapper")
local ManagerCommunication = require("shared/wm/communication")

local ScriptTypes = require("server/scriptManager/scriptTypes")
local Functions = require("shared/functions")

type source = {
	owner: Player,
	source: string,
}

local sources = {
	[ScriptTypes.Script] = {} :: { [string]: source },
	[ScriptTypes.LocalScript] = {} :: { [string]: source },
	[ScriptTypes.ModuleScript] = {} :: { [string]: source },
}
local scripts = {}

local Module = {}

function Module:Init()
	ManagerCommunication:onInvoke("CreateSourceId", function(owner, scriptType, source)
		local id = Functions.randomString(16)
		sources[scriptType][id] = {
			owner = owner,
			source = source,
		}

		return id
	end)

	ManagerCommunication:on("NewWorker", function(owner: Player, source: string, host: ModuleScript, ...)
		local id = Functions.randomString(16)
		sources[ScriptTypes.ModuleScript][id] = {
			owner = owner,
			source = source,
			isWorker = true,
		}

		-- We need an actual host for workers for error catching to work correctly and due to how we track sandboxes (getfenv(0))
		-- We use a modulescript because it allows us to start the script under our actor while the actor is destroyed
		-- Only downside to this is that it will cost a little extra memory for each worker (due to them having their own ModuleScript)
		-- It will still throw warnings on task.desynchronize but doesn't cause any issues as of right now (can be fixed by parenting it into a newly created actor instance)
		host:SetAttribute("source", id)
		task.defer(require, host)
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
				return nil, nil, err
			end

			local sandbox = Sandbox.new(sourceData.owner, if not sourceData.isWorker then hostScript else nil)
			scripts[hostScript] = sandbox
			setfenv(func, sandbox.Environment)

			-- Track the calling thread (this thread)
			sandbox.Threads[coroutine.running()] = true

			return func,
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
			local source, line = string.match(traces[index], "^(.+), line (%d+)$")
			if source == wmSource then
				continue
			end

			ManagerCommunication:Send("info", player, `Script '{source}', Line {line}`)
		end

		ManagerCommunication:Send("info", player, "Stack End")
	end)
end

return Module
