local setmetatable = setmetatable
local shared = shared
local rawequal = rawequal
local error = error
local Instance = Instance
local table = table
local game = game
local task = task
local debug = debug
local string = string
local tonumber = tonumber

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local Sandbox = require("client/wm/sandbox")
local VM = require("client/wm/sandbox/vm")
local ManagerCommunication = require("shared/wm/communication")

local Functions = require("shared/functions")
local ScriptTypes = require("shared/scriptManager/scriptTypes")

local getRunning = VM.getRunning
local getDebugInfo = VM.getDebugInfo
local formatError = VM.formatError

local vmStart = VM.vmStart
local vmEnd = VM.vmEnd

type source = {
	owner: Player,
	error: string?,
	bytecode: buffer?,
	arguments: { n: number } & { any },
	isClientSide: boolean?,
	isWorker: boolean?,
	compiling: boolean?,

	allowed: boolean?,
	promptBindable: RBXScriptSignal?,
}

local sources: { [any]: { [string]: source } } = {
	[ScriptTypes.LocalScript] = {},
	[ScriptTypes.ModuleScript] = {},
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

	ManagerCommunication:onInvoke(
		"CreateSourceId",
		function(owner: Player, scriptType, source: string, arguments: BindableFunction?)
			local data = {
				owner = owner,
				arguments = table.freeze(if arguments then table.pack(arguments:Invoke()) else table.pack()),
				isClientSide = true,
				compiling = true,
			}

			task.spawn(function() -- compile() yields
				local success, result = ManagerCommunication:Invoke("compile", source)
				if not success then
					data.error = result
				else
					data.bytecode = result
				end

				data.compiling = false
			end)

			local id = Functions.randomString(16)
			sources[scriptType][id] = data
			return id
		end
	)

	ManagerCommunication:on(
		"NewWorker",
		function(owner: Player, source: string, host: ModuleScript, arguments: BindableFunction?)
			local data = {
				owner = owner,
				arguments = table.freeze(if arguments then table.pack(arguments:Invoke()) else table.pack()),
				isWorker = true,
				compiling = true,
			}

			task.spawn(function() -- compile() yields
				local success, result = ManagerCommunication:Invoke("compile", source)
				if not success then
					data.error = result
				else
					data.bytecode = result
				end

				data.compiling = false
			end)

			local id = Functions.randomString(16)
			sources[ScriptTypes.ModuleScript][id] = data

			-- We need an actual host for workers for error catching to work correctly and due to how we track sandboxes (getfenv(0))
			-- We use a modulescript because it allows us to start the script under our actor while the actor is destroyed
			-- Only downside to this is that it will cost a little extra memory for each worker (due to them having their own ModuleScript)
			host.Parent = Instance.new("Actor")
			host:SetAttribute("__sb_source", id)
			task.defer(require, host)
		end
	)

	-- TODO: Hook Instance.fromExisting and :Clone() to replace cloned scripts with a version that has the source isClientSide set to true
	ManagerCommunication:on("stopScripts", function(removeServerScripts)
		table.clear(sources[ScriptTypes.LocalScript])
		table.clear(sources[ScriptTypes.ModuleScript])

		for script, data in scripts do
			local source: source = data.source
			Sandbox.terminate(data.sandbox, not removeServerScripts and not (source.isWorker or source.isClientSide))
		end
		table.clear(scripts)
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

			if not hostScript:HasTag("__sb_script") then
				return error("invalid script", 2)
			end

			local sourceId = hostScript:GetAttribute("__sb_source")
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

			while sourceData.compiling do
				task.wait()
			end

			if sourceData.error then
				local err = hostScript:GetFullName() .. sourceData.error

				ManagerCommunication:Send("error", err)
				return nil, nil, nil, err
			end

			local sandbox, sandboxedFunc =
				Sandbox.new(sourceData.owner, sourceData.bytecode, if not sourceData.isWorker then hostScript else nil)
			sandbox.StackSource = hostScript:GetFullName()
			scripts[hostScript] = table.freeze({ sandbox = sandbox, source = sourceData, type = scriptType })

			-- Track the calling thread (this thread)
			sandbox.Threads[coroutine.running()] = true

			return sandboxedFunc,
				sourceData.arguments,
				if className == "Script" or sourceData.isWorker
					then function(thread)
						sandbox.Threads[thread] = true
					end
					else function(...)
						return ...
					end
		end,
	})

	-- Get the source of the worker manager (to work with stack traces)
	local wmSource = debug.info(Functions.empty, "s")

	-- Listen for script errors (defer because it doesn't work otherwise, idk why)
	local ErrorSignal = game:GetService("ScriptContext").Error
	task.defer(ErrorSignal.Connect, ErrorSignal, function(message, stackTrace, script)
		if not scripts[script] then
			return
		end

		local running = getRunning()
		if not running then
			return
		end

		ManagerCommunication:Send("error", formatError(running, message))
		ManagerCommunication:Send("info", "Stack Begin")

		-- Format and filter out sb stack traces
		local traces = string.split(stackTrace, "\n")
		local currentStack = running
		for index = 1, #traces - 1 do -- Last trace is always "" (so we skip it)
			local source, line, func = string.match(traces[index], "^(.+), line (%d+) %- function (.+)$")
			if not func then
				source, line = string.match(traces[index], "^(.+), line (%d+)$")
			end

			-- Check if the stack is external
			if source ~= wmSource then
				if func then
					ManagerCommunication:Send("info", `Script '{source}', Line {line} - function {func}`)
				else
					ManagerCommunication:Send("info", `Script '{source}', Line {line}`)
				end

				continue
			end

			line = tonumber(line)
			if line < vmStart or line > vmEnd then
				-- If the line is before vmStart or after vmEnd, it's not a user owned stack
				continue
			end

			if not currentStack then
				continue
			end

			local vmSource, vmLine, vmFunc = getDebugInfo(currentStack)
			if vmFunc then
				ManagerCommunication:Send("info", `Script '{vmSource}', Line {vmLine or "?"} - function {vmFunc}`)
			else
				ManagerCommunication:Send("info", `Script '{vmSource}', Line {vmLine or "?"}`)
			end

			currentStack = currentStack.stackParent
		end

		ManagerCommunication:Send("info", "Stack End")
	end)
end

return Module
