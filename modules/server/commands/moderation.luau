return function(Commands)
	-- Load shared definitions
	require("shared/commands/moderation")(Commands)

	local namespace = "moderation"
	local function defineValidator(...)
		Commands:DefineValidator(namespace, ...)
	end
	local function define(...)
		Commands:Define(namespace, ...)
	end
end
