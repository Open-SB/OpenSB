local ScriptManager = require("server/scriptManager")
local Output = require("server/output")
local DB = require("server/db")
local Network = require("server/network")

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

local playerScripts: { [Player]: { [string]: { type: any, instance: BaseScript } } } = ScriptManager.PlayerScripts
Players.PlayerRemoving:Connect(function(player)
	playerScripts[player] = nil
end)

local function runScript(player: Player, type, name: string, source: string, parent: Instance?, arguments: table?)
	local runningScripts = playerScripts[player]
	if not runningScripts then
		runningScripts = {}
		playerScripts[player] = runningScripts
	elseif runningScripts[name] ~= nil then
		local index = 1
		while runningScripts[name .. index] ~= nil do
			index += 1
		end

		name ..= index
	end

	local id = Output:appendWithIdTo(player, Output.MessageType.Information, `Compiling "{name}"...`)

	local _, err = loadstring(source, "=" .. name) -- Prefixing with a "=" removes the [string ""] from the chunkname.
	if err then
		Output:dropIdFrom(player, id)
		Output:appendTo(player, Output.MessageType.Error, err)

		return
	end

	local hostScript = ScriptManager:CreateScript(player, type, name, source, arguments)
	runningScripts[name] = { type = type, instance = hostScript }

	Output:editFrom(player, id, Output.MessageType.Information, `Running "{hostScript.Name}"...`)
	Output:dropIdFrom(player, id)
	hostScript.Parent = parent
end

return function(Commands)
	-- Load shared definitions
	require("shared/commands/default")(Commands)

	local _namespace = "default"
	local function defineValidator(...)
		Commands:DefineValidator(_namespace, ...)
	end
	local function define(...)
		Commands:Define(_namespace, ...)
	end

	--:execute
	define("execute", function(context, arguments)
		local source = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		runScript(context.Player, ScriptManager.ScriptType.Script, "Script", source, workspace)
	end)

	--:localExecute
	define("localExecute", function(context, arguments)
		local source = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		runScript(context.Player, ScriptManager.ScriptType.LocalScript, "LocalScript", source, context.Player.PlayerGui)
	end)

	--:httpExecute
	define("httpExecute", function(context, arguments)
		local link = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		local source = HttpService:GetAsync(link)
		runScript(context.Player, ScriptManager.ScriptType.Script, "Script", source, workspace)
	end)

	--:httpLocalExecute
	define("httpLocalExecute", function(context, arguments)
		local link = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		local source = HttpService:GetAsync(link)
		runScript(context.Player, ScriptManager.ScriptType.LocalScript, "LocalScript", source, context.Player.PlayerGui)
	end)

	--:createSourceScript
	define("createSourceScript", function(context, arguments)
		local name = table.remove(arguments, 1)
		local source = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		DB:SaveScript(context.Player.UserId, name, "source", source)
		Network:FireClient(context.Player, "addScript", name)

		return `Created script '{name}'.`
	end)

	--:createHttpScript
	define("createHttpScript", function(context, arguments)
		local name = table.remove(arguments, 1)
		local link = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		DB:SaveScript(context.Player.UserId, name, "http", link)
		Network:FireClient(context.Player, "addScript", name)

		return `Created script '{name}'.`
	end)

	--:removeScript
	define("removeScript", function(context, arguments)
		local name = arguments[1]
		DB:RemoveScript(context.Player.UserId, name)
		Network:FireClient(context.Player, "removeScript", name)

		return `Removed script '{name}'.`
	end)

	--:renameScript
	define("renameScript", function(context, arguments)
		local name = arguments[1]
		local newName = arguments[2]
		local userId = context.Player.UserId

		local script = DB:GetScript(userId, name)
		if not script then
			return false, `Script '{name}' doesn't exist.`
		end

		DB:SaveScript(userId, newName, script.sourceType, script.source)
		DB:RemoveScript(userId, name)

		Network:FireClient(context.Player, "addScript", newName)
		Network:FireClient(context.Player, "removeScript", name)

		return `Renamed script '{name}' to '{newName}'.`
	end)

	--:runScript
	define("runScript", function(context, arguments)
		local name = table.remove(arguments, 1)
		local script = DB:GetScript(context.Player.UserId, name)
		if not script then
			return false, `Script '{name}' doesn't exist.`
		end

		local source = if script.sourceType == "http" then HttpService:GetAsync(script.source) else script.source
		runScript(context.Player, ScriptManager.ScriptType.Script, name, source, workspace, arguments)
	end)

	--:runLocalScript
	define("runLocalScript", function(context, arguments)
		local name = table.remove(arguments, 1)
		local script = DB:GetScript(context.Player.UserId, name)
		if not script then
			return false, `Script '{name}' doesn't exist.`
		end

		local source = if script.sourceType == "http" then HttpService:GetAsync(script.source) else script.source
		runScript(
			context.Player,
			ScriptManager.ScriptType.LocalScript,
			name,
			source,
			context.Player.PlayerGui,
			arguments
		)
	end)

	--:stopScript
	define("stopScript", function(context, arguments)
		local scriptName = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.

		local runningScripts = playerScripts[context.Player]
		if not runningScripts then
			return false, `No script called '{scriptName}' is running.`
		end

		local script = runningScripts[scriptName]
		if not script then
			return false, `No script called '{scriptName}' is running.`
		end

		ScriptManager:StopScript(script.instance)
		runningScripts[scriptName] = nil

		return `Stopped script '{scriptName}'.`
	end)
end
