return function(Commands)
	local definitions = require("shared/commands/namespaces/default.toml")
	local _namespace = "default"
	Commands:RegisterNamespace(_namespace, definitions)

	local function defineValidator(...)
		Commands:DefineValidator(_namespace, ...)
	end
	local function define(...)
		Commands:Define(_namespace, ...)
	end

	--:execute
	defineValidator("execute", function(_, arguments)
		return arguments[1], "No source was given."
	end)

	--:localExecute
	defineValidator("localExecute", function(_, arguments)
		return arguments[1], "No source was given."
	end)

	--:httpExecute
	defineValidator("httpExecute", function(_, arguments)
		return arguments[1], "No link was given."
	end)

	--:httpLocalExecute
	defineValidator("httpLocalExecute", function(_, arguments)
		return arguments[1], "No link was given."
	end)
end
