local ScriptManager = require("server/scriptManager")
local Output = require("server/output")

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
		local scriptName = "Script"
		local id = Output:appendWithIdTo(context.Player, Output.MessageType.Information, `Compiling "{scriptName}"...`)

		local source = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		local _, err = loadstring(source, "=" .. scriptName) -- Prefixing with a "=" removes the [string ""] from the chunkname.
		if err then
			Output:dropIdFrom(context.Player, id)
			Output:appendTo(context.Player, Output.MessageType.Error, err)

			return
		end

		local hostScript =
			ScriptManager:CreateScript(context.Player, ScriptManager.ScriptType.Script, scriptName, source)
		Output:editFrom(context.Player, id, Output.MessageType.Information, `Running "{hostScript.Name}"...`)
		Output:dropIdFrom(context.Player, id)
		hostScript.Parent = workspace
	end)

	--:localExecute
	define("localExecute", function(context, arguments)
		local scriptName = "LocalScript"
		local id = Output:appendWithIdTo(context.Player, Output.MessageType.Information, `Compiling "{scriptName}"...`)

		local source = table.concat(arguments, "/") -- The "/" key is used as the argument delimiter.
		local _, err = loadstring(source, "=" .. scriptName) -- Prefixing with a "=" removes the [string ""] from the chunkname.
		if err then
			Output:dropIdFrom(context.Player, id)
			Output:appendTo(context.Player, Output.MessageType.Error, err)

			return
		end

		local hostScript =
			ScriptManager:CreateScript(context.Player, ScriptManager.ScriptType.LocalScript, scriptName, source)
		Output:editFrom(context.Player, id, Output.MessageType.Information, `Running "{hostScript.Name}"...`)
		Output:dropIdFrom(context.Player, id)
		hostScript.Parent = context.Player.PlayerGui
	end)
end
