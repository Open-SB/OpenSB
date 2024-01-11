return function(Commands)
	local definitions = require("shared/commands/namespaces/get.toml")
	local namespace = "get"
	Commands:RegisterNamespace(namespace, definitions)

	local function defineValidator(...)
		Commands:DefineValidator(namespace, ...)
	end
	local function define(...)
		Commands:Define(namespace, ...)
	end
end
