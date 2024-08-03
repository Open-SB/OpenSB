local ScriptManager = require("server/scriptManager")
local Output = require("server/output")

local function runScript(player, type, name, source, parent)
	local id = Output:appendWithIdTo(player, Output.MessageType.Information, `Compiling "{name}"...`)

	local _, err = loadstring(source, "=" .. name) -- Prefixing with a "=" removes the [string ""] from the chunkname.
	if err then
		Output:dropIdFrom(player, id)
		Output:appendTo(player, Output.MessageType.Error, err)

		return
	end

	local hostScript = ScriptManager:CreateScript(player, type, name, source)
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
end
