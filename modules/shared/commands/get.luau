local Functions = require("shared/functions")

return function(Commands)
	local definitions = require("shared/commands/namespaces/get.toml")
	local _namespace = "get"
	Commands:RegisterNamespace(_namespace, definitions)

	local function defineValidator(...)
		Commands:DefineValidator(_namespace, ...)
	end
	local function define(...)
		Commands:Define(_namespace, ...)
	end

	--:rejoin
	defineValidator("rejoin", function()
		return Functions.getServerType() ~= "VIPServer", "You can't use rejoin command in VIP servers."
	end)
end
