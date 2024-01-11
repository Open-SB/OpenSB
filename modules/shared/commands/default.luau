return function(Commands)
	local definitions = require("shared/commands/namespaces/default.toml")
	local namespace = "default"
	Commands:RegisterNamespace(namespace, definitions)

	local function defineValidator(...)
		Commands:DefineValidator(namespace, ...)
	end
	local function define(...)
		Commands:Define(namespace, ...)
	end
end
