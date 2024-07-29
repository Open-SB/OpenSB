local setmetatable = setmetatable
local shared = shared
local rawequal = rawequal
local error = error
local Instance = Instance
local table = table

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local Sandbox = require("client/wm/sandbox")
local ManagerCommunication = require("shared/wm/communication")

local ScriptTypes = require("shared/scriptManager/scriptTypes")

type source = {
	owner: Player,
	error: string?,
	bytecode: string?,
	arguments: { n: number } & { any },

	allowed: boolean?,
	promptBindable: RBXScriptSignal?,
}

local sources = {
	[ScriptTypes.LocalScript] = {} :: { [string]: source },
	[ScriptTypes.ModuleScript] = {} :: { [string]: source },
}
local scripts = {}
local toPrompt = {}

local localPlayer = Players.LocalPlayer

local Module = {}

local function prompt(sourceData: source, script: BaseScript)
	if sourceData.allowed == false then
		-- User has not allowed this script
		return false
	elseif sourceData.allowed == true then
		-- User has allowed this script
		return true
	end

	-- User hasn't been prompted for this script, or didn't answer last time
	if sourceData.promptBindable then
		-- User is already getting prompted for this script, don't make another prompt
		return sourceData.promptBindable:Wait() or false
	end

	local bindable = Instance.new("BindableEvent")
	sourceData.promptBindable = bindable.Event

	-- We send the bindable and everything to eventually be handled by another thread, so nothing wrong happens if the host script stops
	table.insert(toPrompt, { bindable, sourceData, script })
	return bindable.Event:Wait() or false
end

function Module:Init()
	RunService.PreRender:Connect(function()
		for _, data in ipairs(toPrompt) do
			local bindable, sourceData, script = unpack(data)
			ManagerCommunication:Send("makeScriptPrompt", bindable, sourceData.owner, script)
			bindable.Event:Once(function(allowed)
				sourceData.allowed = allowed
				sourceData.promptBindable = nil

				-- Defer so other connections has a chance to fire
				task.defer(bindable.Destroy, bindable)
			end)
		end
		table.clear(toPrompt)
	end)

	setmetatable(_G, { __metatable = "The metatable is locked" })
	setmetatable(shared, {
		__metatable = "The metatable is locked",
		__call = function(_, key, hostScript)
			if typeof(hostScript) ~= "Instance" then
				return error("invalid script", 2)
			end

			-- Pcall while obtaining the ClassName prevents any Ro bloxLocked instance from throwing an error here
			local className: string?
			pcall(function()
				className = hostScript.ClassName
			end)

			-- Use rawequal to bypass potential __eq metamethods
			if className == "LocalScript" then
				if not rawequal(key, _G.localScriptHostKey) then
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

			local scriptType = if className == "LocalScript" then ScriptTypes.LocalScript else ScriptTypes.ModuleScript
			local sourceData = sources[scriptType][sourceId]
			if not sourceData then
				sourceData = ManagerCommunication:Invoke("fetchSource", scriptType, sourceId)
				if not sourceData then
					return error("invalid script", 2)
				end

				sources[scriptType][sourceId] = sourceData
			end

			if sourceData.owner ~= localPlayer and not prompt(sourceData, hostScript) then
				-- User doesn't own this script and doesn't allow it to run
				return error("script not allowed to run", 2)
			end

			if sourceData.error then
				local err = hostScript:GetFullName() .. sourceData.error

				ManagerCommunication:Send("error", err)
				return nil, nil, err
			end

			local sandbox, sandboxedFunc =
				Sandbox.new(sourceData.owner, sourceData.bytecode, if not sourceData.isWorker then hostScript else nil)
			scripts[hostScript] = sandbox

			-- Track the calling thread (this thread)
			sandbox.Threads[coroutine.running()] = true

			return sandboxedFunc, sourceData.arguments
		end,
	})
end

return Module
