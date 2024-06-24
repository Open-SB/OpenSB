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

	local sourceId = WorkerManagers.main:Invoke("CreateSourceId", owner, scriptType, source)
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

return Module
