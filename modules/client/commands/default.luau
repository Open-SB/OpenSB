return function(Commands)
	-- Load shared definitions
	require("shared/commands/default")(Commands)

	local namespace = "default"
	local function defineValidator(...)
		Commands:DefineValidator(namespace, ...)
	end
	local function define(...)
		Commands:Define(namespace, ...)
	end
end
