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
end
