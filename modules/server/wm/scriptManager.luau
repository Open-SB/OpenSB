local setmetatable = setmetatable
local shared = shared
local typeof = typeof
local error = error
local pcall = pcall
local rawequal = rawequal
local loadstring = loadstring
local getfenv = getfenv
local coroutine = coroutine

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

local Module = {}

function Module:Init()
	ManagerCommunication:onInvoke("CreateSourceId", function(owner, scriptType, source, name)
		local id = Functions.randomString(16)
		sources[scriptType][id] = {
			owner = owner,
			source = source,
		}

		return id
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
				return nil, nil, err
			end

			local scriptSandbox = Sandbox.new(sourceData.owner, hostScript)
			setfenv(func, scriptSandbox.Environment)

			-- Track the calling thread (this thread)
			scriptSandbox.Threads[coroutine.running()] = true

			return func,
				if className == "Script"
					then function(thread)
						scriptSandbox.Threads[thread] = true
					end
					else function(...)
						return Wrapper.unwrapMany(...)
					end
		end,
	})
end

return Module
