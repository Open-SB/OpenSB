local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local UserInputService = game:GetService("UserInputService")

local Network = require("@client/network")
local Output = require("@client/output")
local ProcessResult = require("@shared/commands/processResults")
local InputContext = require("@shared/commands/inputContexts")
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

function Commands:CreateContext(command, input, inputContext)
	local context = {
		Command = command,
		Player = Players.LocalPlayer,
		RawInput = input,
		InputContext = inputContext,

		Data = {},
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

function Commands:ProcessServer(prefix, commandName, arguments, contextData, input, inputContext)
	contextData.prefix = prefix
	contextData.commandName = commandName
	contextData.arguments = arguments
	return Network:InvokeServer("processCommand", contextData, input, inputContext)
end

function Commands:ProcessClient(namespace, commandName, arguments, input, inputContext)
	local command = namespace.commandLookup[string.lower(commandName)]
	if not command then
		return ProcessResult.Fail, `Command "{commandName}" was not found.`
	end

	local context = Commands:CreateContext(command, input, inputContext)
	local valid, message = Commands:Validate(command, context, arguments)
	if not valid then
		return ProcessResult.Error, message
	end

	local success, commandMessage = Commands:Run(command, context, arguments)
	if not success then
		return ProcessResult.Error, commandMessage
	end

	return ProcessResult.Success, commandMessage, context.Data
end

function Commands:Process(input, inputContext)
	-- Check if the input matches a command string, if not then we can silently ignore it.
	if not string.match(input, "^.+/") then
		return
	end

	local arguments = string.split(input, "/")
	local prefix = table.remove(arguments, 1)
	if not prefix then
		Output:append(Output.MessageType.Error, "No prefix was found.")
		return
	end

	-- Remove last argument if empty.
	if #arguments[#arguments] == 0 then
		table.remove(arguments, #arguments)
	end

	-- Find namespace, and get the command.
	local commandName
	local namespace = Commands.namespaceLookup[string.lower(prefix)]
	if not namespace then
		-- No namespace with prefix found, default namespace, command should be the 1st split string (command/arguments).
		commandName = prefix
		namespace = Commands.namespaces.default
	elseif arguments[1] and #arguments[1] > 0 then -- Check if there is a 2nd split string, otherwise no command was given.
		-- Not default namespace, command should be the 2nd split string (prefix/command/arguments).
		commandName = table.remove(arguments, 1)
	else
		Output:append(Output.MessageType.Error, "No command was given.")
		return
	end
	commandName = commandName:split(" ")

	for i, commandName in pairs(commandName) do
		local clientResult, clientMessage, contextData =
			Commands:ProcessClient(namespace, commandName, arguments, input, inputContext)
		if clientResult ~= ProcessResult.Success then
			-- Only output fail messages if the inputContext wasn't the chat (because you can also send chat messages in chat, duh),
			-- Error messages should always be displayed.
			if
				clientResult == ProcessResult.Error
				or (clientResult == ProcessResult.Fail and inputContext ~= InputContext.Chat)
			then
				Output:append(
					Output.MessageType.Error,
					clientMessage or "Unexpected error occured while running command."
				)
			end

			continue
		elseif clientMessage then
			Output:append(Output.MessageType.Success, clientMessage)
		end

		local serverResult, serverMessage =
			Commands:ProcessServer(prefix, commandName, arguments, contextData, input, inputContext)
		if serverResult ~= ProcessResult.Success then
			-- We don't check if the ProcessResult was a Fail or Error here, because it should always be an Error.
			Output:append(Output.MessageType.Error, serverMessage or "Unexpected error occured while running command.")
			continue
		elseif serverMessage then
			Output:append(Output.MessageType.Success, serverMessage)
		end
	end
end

function Commands:Init(namespaces)
	Log.debug("Loading commands...")

	TextChatService.SendingMessage:Connect(function(message)
		-- For some reason, SendAsync doesn't work in sandbox??? So this is perfectly safe.
		-- At this stage, chat filter isn't actually invoked, so this works perfectly.

		local preferredInput = UserInputService.PreferredInput
		if
			(
				preferredInput == Enum.PreferredInput.KeyboardAndMouse
				and not UserInputService:IsKeyDown(Enum.KeyCode.Return)
			)
			or (
				preferredInput == Enum.PreferredInput.Gamepad
				and not UserInputService:IsGamepadButtonDown(
					UserInputService:GetNavigationGamepads()[1],
					Enum.KeyCode.ButtonStart
				)
			)
		then
			return
		end

		Commands:Process(message.Text, InputContext.Chat)
	end)

	-- Load Namespaces
	for _, namespace in ipairs(namespaces) do
		namespace(self)
	end
end

return Commands
