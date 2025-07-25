local Output = require("@server/output")
local Network = require("@server/network")
local compile = require("@server/compile")
local Assets = require("@shared/assets")
local WorkerManagers = require("@shared/workerManagers")
local DB = require("@server/db")
local PlayerList = require("@shared/playerList")

local ScriptTypes = require("@shared/scriptManager/scriptTypes")

local playerScripts: { [Player]: { [string]: { type: any, instance: BaseScript } } } = {}

local Module = {}
Module.ScriptType = ScriptTypes
Module.PlayerScripts = playerScripts

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
	[ScriptTypes.Script] = getHost("script"),
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

function Module:StopScript(script: BaseScript)
	WorkerManagers.main:Send("stopScript", script)
end

function Module:StopScripts(player: Player?)
	if player then
		playerScripts[player] = nil
	else
		table.clear(playerScripts)
	end

	WorkerManagers:Send("stopScripts", player, true)
end

local function removeScripts(list: typeof(playerScripts)?, scriptType: number)
	if not list then
		return
	end

	for name, script in list do
		if script.type == scriptType then
			list[name] = nil
		end
	end
end

function Module:StopServerScripts(player: Player?)
	if player then
		removeScripts(playerScripts[player], ScriptTypes.Script)
	else
		for _, list in playerScripts do
			removeScripts(list, ScriptTypes.Script)
		end
	end

	WorkerManagers:Send("stopScripts", player, true, ScriptTypes.Script)
end

function Module:StopLocalScripts(player: Player?)
	if player then
		removeScripts(playerScripts[player], ScriptTypes.LocalScript)
	else
		for _, list in playerScripts do
			removeScripts(list, ScriptTypes.LocalScript)
		end
	end

	WorkerManagers:Send("stopScripts", player, false, ScriptTypes.LocalScript)
end

Network:RegisterFunction("getScriptList", function(player: Player)
	return DB:GetScripts(player.UserId)
end)

Network:RegisterFunction("fetchSource", function(player: Player, scriptType, sourceId: string)
	if not scriptType or type(sourceId) ~= "string" then
		return
	elseif scriptType ~= ScriptTypes.LocalScript and scriptType ~= ScriptTypes.ModuleScript then
		return
	end

	return WorkerManagers.main:Invoke("fetchSource", player, scriptType, sourceId)
end)

Network:RegisterFunction("compile", function(_, source: string)
	if type(source) ~= "string" then
		return
	end

	return compile(source)
end)

Network:RegisterFunction(
	"newScript",
	function(player: Player, owner: Player, parent: Instance?, source: source, arguments: table)
		if player ~= owner then
			return
		end

		if type(source) ~= "string" or type(arguments) ~= "table" or type(arguments.n) ~= "number" then
			return
		end

		if typeof(parent) ~= "Instance" then
			return false
		end

		local script = Module:CreateScript(owner, ScriptTypes.Script, nil, source, arguments)
		script.Parent = parent

		return script
	end
)

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

WorkerManagers:onInvoke("newScript", function(owner: Player, source: string, arguments: (table | BindableFunction)?)
	return Module:CreateScript(owner, ScriptTypes.Script, nil, source, arguments)
end)

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

PlayerList.Removed:Connect(function(player: Player)
	Module:StopScripts(player)
end)

return Module
