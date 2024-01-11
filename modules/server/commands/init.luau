local string = string
local table = table
local ipairs = ipairs
local type = type

local Network = require("server/network")
local Log = require("shared/log")

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

	local success, message = pcall(command.callback, context, arguments)
	if not success then
		Log.warn(message)
		return false
	end

	return true
end

function Commands:Process(player, data, input, inputContext)
	-- Check if the input matches a command string, if not then we can ignore it.
	if not string.match(input, "^.+/") then
		return false
	end

	local arguments = string.split(input, "/")
	local prefix = table.remove(arguments, 1)
	if not prefix then
		return false
	end

	-- Find namespace, and get the command.
	local commandName
	local namespace = Commands.namespaceLookup[string.lower(prefix)]
	if not namespace then
		-- No namespace with prefix found, default namespace, command should be the 1st split string (command/arguments).
		commandName = prefix
		namespace = Commands.namespaces.default
	elseif #arguments > 0 then -- Check if there is a 2nd split string, otherwise no command was given.
		-- Not default namespace, command should be the 2nd split string (prefix/command/arguments).
		commandName = table.remove(arguments, 1)
	else
		return false
	end

	local command = namespace.commandLookup[string.lower(commandName)]
	if not command then
		return false
	end

	local context = Commands:CreateContext(player, data, command, input, inputContext)
	local valid, message = Commands:Validate(command, context, arguments)
	if not valid then
		Log.warn(message)
		return false
	end

	return Commands:Run(command, context, arguments)
end

function Commands:Init()
	Log.debug("Loading commands...")

	Network:RegisterFunction("processCommand", function(player, data, input, inputContext)
		if
			type(data) ~= "table"
			or type(input) ~= "string"
			or (type(inputContext) ~= "string" and inputContext ~= nil)
		then
			return false, "Invalid data"
		end

		return Commands:Process(player, data, input, inputContext)
	end)

	-- Load Namespaces
	require("./default")(self)
	require("./get")(self)
end

return Commands