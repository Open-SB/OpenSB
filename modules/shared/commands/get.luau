return function(Commands)
	local definitions = require("@shared/commands/namespaces/get.toml")
	local _namespace = "get"
	Commands:RegisterNamespace(_namespace, definitions)

	local function defineValidator(...)
		Commands:DefineValidator(_namespace, ...)
	end
	local function define(...)
		Commands:Define(_namespace, ...)
	end
end
