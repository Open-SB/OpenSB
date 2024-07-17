local WorkerManagers = require("shared/workerManagers")
local Output = require("server/output")

local ScriptTypes = require("./scriptTypes")

local Module = {}
Module.ScriptType = ScriptTypes

local function getHost(name)
	local host = game:GetService("ServerScriptService"):WaitForChild(name)
	host.Parent = nil

	if host.ClassName ~= "ModuleScript" then
		host.Enabled = true
	end

	return host
end

local scriptHosts = {
	[ScriptTypes.Script] = getHost("scriptHost"),
	[ScriptTypes.LocalScript] = getHost("localScriptHost"),
	[ScriptTypes.ModuleScript] = getHost("moduleScriptHost"),
	Worker = getHost("workerHost"),
}

function Module:CreateScript(owner, scriptType, name, source, arguments): BaseScript
	assert(owner, "No owner given.")
	assert(scriptType, "No script type given.")
	assert(ScriptTypes[scriptType], "Invalid script type.")
	assert(name == nil or type(name) == "string", "Invalid name datatype.")
	assert(source, "No source given.")
	assert(arguments == nil or type(arguments) == "table", "Invalid arguments datatype.")

	if not name then
		if scriptType == ScriptTypes.LocalScript then
			name = "LocalScript"
		elseif scriptType == ScriptTypes.ModuleScript then
			name = "ModuleScript"
		else
			name = "Script"
		end
	end

	local sourceId = WorkerManagers.main:Invoke(
		"CreateSourceId",
		owner,
		scriptType,
		source,
		if arguments then table.clone(arguments) else nil
	)
	local host = scriptHosts[scriptType]:Clone()
	host.Name = name
	host:SetAttribute("source", sourceId) -- TODO: Protect attribute, or find another way of setting it that is copyable via :Clone()

	return host
end

WorkerManagers:on("log", function(player: Player, message: string)
	Output:appendTo(player, Output.MessageType.Log, message)
end)

WorkerManagers:on("warn", function(player: Player, message: string)
	Output:appendTo(player, Output.MessageType.Warning, message)
end)

WorkerManagers:on("error", function(player: Player, message: string)
	Output:appendTo(player, Output.MessageType.Error, message)
end)

WorkerManagers:on("info", function(player: Player, message: string)
	Output:appendTo(player, Output.MessageType.Information, message)
end)

WorkerManagers:onInvoke("newScript", function(owner: Player, source: string, ...)
	return Module:CreateScript(owner, ScriptTypes.Script, nil, source, table.pack(...))
end)

WorkerManagers:onInvoke("newLocalScript", function(owner: Player, source: string, ...)
	return Module:CreateScript(owner, ScriptTypes.LocalScript, nil, source, table.pack(...))
end)

WorkerManagers:onInvoke("newModuleScript", function(owner: Player, source: string, ...)
	return Module:CreateScript(owner, ScriptTypes.ModuleScript, nil, source, table.pack(...))
end)

do
	local currentWorker = 1
	WorkerManagers:on("newWorker", function(owner: Player, source: string, name: string, ...)
		local host = scriptHosts.Worker:Clone()
		host.Name = name

		WorkerManagers[currentWorker]:Send("NewWorker", owner, source, host, table.pack(...))

		-- Round robin is used to split up workers
		currentWorker = currentWorker % _G.workerThreads + 1
	end)
end

return Module
