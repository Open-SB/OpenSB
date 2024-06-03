local WorkerManagers = require("shared/workerManagers")

local ScriptTypes = require("./scriptTypes")

local Module = {}
Module.ScriptType = ScriptTypes

local function getHost(name)
	local host = game:GetService("ServerScriptService"):WaitForChild(name)
	host.Parent = nil

	return host
end

local scriptHosts = {
	[ScriptTypes.Script] = getHost("scriptHost"),
	[ScriptTypes.LocalScript] = getHost("localScriptHost"),
}

function Module:CreateScript(owner, scriptType, name, source, arguments): BaseScript
	assert(owner, "No owner given.")
	assert(scriptType, "No script type given.")
	assert(ScriptTypes[scriptType], "Invalid script type.")
	assert(name == nil or type(name) == "string", "Invalid name datatype.")
	assert(source, "No source given.")
	assert(arguments == nil or type(arguments) == "table", "Invalid arguments datatype.")

	if not name then
		name = if scriptType == ScriptTypes.LocalScript then "LocalScript" else "Script"
	end

	local sourceId =
		WorkerManagers.main:Invoke("CreateSourceId", owner, source, name, scriptType == ScriptTypes.LocalScript) -- 3rd arg is if to compile.
	local host = scriptHosts[scriptType]:Clone()
	host.Name = name
	host.Enabled = true
	host:SetAttribute("source", sourceId) -- TODO: Protect attribute, or find another way of setting it that is copyable via :Clone()

	return host
end

return Module
