return function(Commands)
	local definitions = require("@shared/commands/namespaces/default.toml")
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

	--:createSourceScript
	defineValidator("createSourceScript", function(_, arguments)
		if not arguments[1] then
			return false, "No script name was given."
		end

		if not arguments[2] then
			return false, "No script source was given."
		end

		return true
	end)

	--:createHttpScript
	defineValidator("createHttpScript", function(_, arguments)
		if not arguments[1] then
			return false, "No script name was given."
		end

		if not arguments[2] then
			return false, "No script source was given."
		end

		return true
	end)

	--:removeScript
	defineValidator("removeScript", function(_, arguments)
		return arguments[1], "No script name was given."
	end)

	--:renameScript
	defineValidator("renameScript", function(_, arguments)
		if not arguments[1] then
			return false, "No script name was given."
		end

		if not arguments[2] then
			return false, "No new script name was given."
		end

		if arguments[1] == arguments[2] then
			return false, "The new script name cannot be the same as the old one."
		end

		return true
	end)

	--:runScript
	defineValidator("runScript", function(_, arguments)
		return arguments[1], "No script name was given."
	end)

	--:runLocalScript
	defineValidator("runLocalScript", function(_, arguments)
		return arguments[1], "No script name was given."
	end)

	--:stopScript
	defineValidator("stopScript", function(_, arguments)
		return arguments[1], "No script name was given."
	end)
end
