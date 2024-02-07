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
end
