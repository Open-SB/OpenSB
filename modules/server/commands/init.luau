local Network = require("@server/network")
local ProcessResult = require("@shared/commands/processResults")
local InputContexts = require("@shared/commands/inputContexts")
local Log = require("@shared/log")

local Commands = {}
Commands.namespaces = {}
Commands.namespaceLookup = {}

function Commands:RegisterNamespace(namespace, definitions)
	local prefixes = definitions._prefixes
	definitions._prefixes = nil

	local namespaceData = {
		prefixes = prefixes,
		commands = definitions,
		commandLookup = {},
	}

	if prefixes then
		for _, prefix in ipairs(prefixes) do
			Commands.namespaceLookup[string.lower(prefix)] = namespaceData
		end
	end

	for _, command in namespaceData.commands do
		for _, alias in ipairs(command.aliases) do
			namespaceData.commandLookup[string.lower(alias)] = command
		end
	end

	Commands.namespaces[namespace] = namespaceData
end

function Commands:DefineValidator(namespace, command, validator)
	Commands.namespaces[namespace].commands[command].validate = validator
end

function Commands:Define(namespace, command, callback)
	Commands.namespaces[namespace].commands[command].callback = callback
end

function Commands:CreateContext(player, data, command, input, inputContext)
	local context = {
		Command = command,
		Player = player,
		RawInput = input,
		InputContext = inputContext,

		Data = data,
	}

	return context
end

function Commands:Validate(command, context, arguments)
	if not command.validate then
		return true
	end

	return command.validate(context, arguments)
end

function Commands:Run(command, context, arguments)
	if not command.callback then
		return true
	end

	local success, result, message = pcall(command.callback, context, arguments)
	if not success then
		return false, `Command runtime error: {result}`
	end

	if type(result) == "boolean" then
		return result, message
	end

	return true, result
end

function Commands:Process(player, data, input, inputContext)
	local prefix, arguments, commandName = data.prefix, data.arguments, data.commandName
	local namespace = Commands.namespaceLookup[string.lower(prefix)]
	if not namespace then
		-- No namespace with prefix found, default namespace, command should be the 1st split string (command/arguments).
		namespace = Commands.namespaces.default
	end

	local command = namespace.commandLookup[string.lower(commandName)]
	if not command then
		return ProcessResult.Fail, `Command "{commandName}" was not found.`
	end

	local context = Commands:CreateContext(player, data, command, input, inputContext)
	local valid, message = Commands:Validate(command, context, arguments)
	if not valid then
		return ProcessResult.Error, message
	end

	local success, commandMessage = Commands:Run(command, context, arguments)
	if not success then
		return ProcessResult.Error, commandMessage
	end

	return ProcessResult.Success, commandMessage
end

function Commands:Init(namespaces)
	Log.debug("Loading commands...")

	Network:RegisterFunction("processCommand", function(player, data, input, inputContext)
		if
			type(data) ~= "table"
			or type(input) ~= "string"
			or inputContext == nil
			or InputContexts[inputContext] == nil
		then
			return ProcessResult.Error, "Invalid command data."
		end

		return Commands:Process(player, data, input, inputContext)
	end)

	-- Load Namespaces
	for _, namespace in ipairs(namespaces) do
		namespace(self)
	end
end

return Commands
