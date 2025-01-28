local Output = require("client/output")
local Network = require("client/network")
local UI = require("client/ui")
local Assets = require("shared/assets")
local WorkerManagers = require("shared/workerManagers")

local ScriptTypes = require("shared/scriptManager/scriptTypes")

local Module = {}
Module.ScriptType = ScriptTypes

local hosts = Assets:get("hosts")
local function getHost(name)
	local host = hosts:WaitForChild(name)
	host.Parent = nil

	if host.ClassName ~= "ModuleScript" then
		host.Enabled = true
	end

	return host
end

local scriptHosts = {
	[ScriptTypes.LocalScript] = getHost("localScript"),
	[ScriptTypes.ModuleScript] = getHost("moduleScript"),
	Worker = getHost("worker"),
}

function Module:CreateScript(owner, scriptType, name, source, arguments: (table | BindableFunction)?): BaseScript
	assert(owner, "No owner given.")
	assert(scriptType, "No script type given.")
	assert(ScriptTypes[scriptType], "Invalid script type.")
	assert(name == nil or type(name) == "string", "Invalid name datatype.")
	assert(source, "No source given.")
	assert(
		arguments == nil
			or type(arguments) == "table"
			or (typeof(arguments) == "Instance" and arguments.ClassName == "BindableFunction"),
		"Invalid arguments datatype."
	)

	if not name then
		if scriptType == ScriptTypes.LocalScript then
			name = "LocalScript"
		elseif scriptType == ScriptTypes.ModuleScript then
			name = "ModuleScript"
		else
			name = "Script"
		end
	end

	if type(arguments) == "table" then
		local list = arguments
		arguments = Instance.new("BindableFunction")
		arguments.OnInvoke = function()
			-- Single use
			arguments.OnInvoke = function() end
			arguments:Destroy()

			return unpack(list, 1, list.n or #list)
		end
	end

	local sourceId = WorkerManagers.main:Invoke("CreateSourceId", owner, scriptType, source, arguments)
	local host = scriptHosts[scriptType]:Clone()
	host.Name = name
	host:SetAttribute("__sb_source", sourceId) -- TODO: Protect attribute
	host:AddTag("__sb_script") -- TODO: Protect tag

	return host
end

function Module:StopScripts()
	WorkerManagers:Send("stopScripts", true)
end

function Module:StopLocalScripts()
	WorkerManagers:Send("stopScripts", false)
end

WorkerManagers:onInvoke("fetchSource", function(scriptType, sourceId: string)
	return Network:InvokeServer("fetchSource", scriptType, sourceId)
end)

WorkerManagers:onInvoke("compile", function(source: string)
	return Network:InvokeServer("compile", source)
end)

WorkerManagers:on("makeScriptPrompt", function(bindable: BindableEvent, owner: Player, script: BaseScript)
	UI:MakeScriptPrompt(bindable, owner, script)
end)

WorkerManagers:on("log", function(message: string)
	Output:append(Output.MessageType.Log, message)
end)

WorkerManagers:on("warn", function(message: string)
	Output:append(Output.MessageType.Warning, message)
end)

WorkerManagers:on("error", function(message: string)
	Output:append(Output.MessageType.Error, message)
end)

WorkerManagers:on("info", function(message: string)
	Output:append(Output.MessageType.Information, message)
end)

WorkerManagers:onInvoke(
	"newScript",
	function(owner: Player, parent: Instance, source: string, arguments: (table | BindableFunction)?)
		if type(arguments) == "Instance" and arguments.ClassName == "BindableFunction" then
			arguments = table.pack(arguments:Invoke())
		end

		return Network:InvokeServer("newScript", owner, parent, source, arguments)
	end
)

WorkerManagers:onInvoke(
	"newLocalScript",
	function(owner: Player, source: string, arguments: (table | BindableFunction)?)
		return Module:CreateScript(owner, ScriptTypes.LocalScript, nil, source, arguments)
	end
)

WorkerManagers:onInvoke(
	"newModuleScript",
	function(owner: Player, source: string, arguments: (table | BindableFunction)?)
		return Module:CreateScript(owner, ScriptTypes.ModuleScript, nil, source, arguments)
	end
)

do
	local currentWorker = 1
	WorkerManagers:on("newWorker", function(owner: Player, source: string, name: string, arguments: table?)
		local host = scriptHosts.Worker:Clone()
		host.Name = name

		if _G.workerThreads < 1 then
			WorkerManagers.main:Send("NewWorker", owner, source, host, arguments)
		else
			WorkerManagers[currentWorker]:Send("NewWorker", owner, source, host, arguments)

			-- Round robin is used to split up workers
			currentWorker = currentWorker % _G.workerThreads + 1
		end
	end)
end

return Module
