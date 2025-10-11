--!strict

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

function Commands:Run(command, context, arguments): (boolean, string?)
	if not command.callback then
		return true, nil
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

function Commands:ProcessServer(data, input, inputContext)
	return Network:InvokeServer("processCommand", data, input, inputContext)
end

type CommandExecutionResult = {
	message: string?,
	name: string,
	intent: string,
} & ({
	result: "fail" | "error",
	data: nil,
} | {
	result: "success",
	data: unknown,
})

-- Please note we must process `g/no. sr c fl fc day d/10 rd/10`
-- but we must not process `g c x/...`
function Commands:ProcessClient(input: string, inputContext): { CommandExecutionResult }
	local namespaceString, remainderOfString = string.match(input, "^(%a+)/(.+)$")

	if not namespaceString or not remainderOfString then
		return { {
			message = "Not a valid command string.",
			result = "fail",
		} :: CommandExecutionResult }
	end

	local results: { CommandExecutionResult } = {}
	local namespace = Commands.namespaceLookup[namespaceString]

	-- HACK: treat x/ c/ l/ etc. as one fragment
	local possibleCommandFragments: { string } = if namespace
		then string.split(remainderOfString, " ")
		else { namespaceString .. "/" .. remainderOfString }

	if not namespace then
		namespace = Commands.namespaces.default
	end

	for _, maybeACommandString: string in possibleCommandFragments do
		local arguments = string.split(maybeACommandString, "/")
		local commandName = table.remove(arguments, 1)

		if not commandName then
			continue
		end

		-- intent is the version of the command the server can understand
		-- e.g g/d/10 rd/10 -> g/d/10 <BREAK> g/rd/10
		local intent = if namespace == Commands.namespaces.default
			then maybeACommandString
			else namespaceString .. "/" .. maybeACommandString

		-- Remove last argument if it exists and if it is empty.
		if arguments[#arguments] and #arguments[#arguments] == 0 then
			table.remove(arguments, #arguments)
		end

		local command = namespace.commandLookup[string.lower(commandName)]
		if not command then
			print(namespaceString, commandName, arguments)
			table.insert(
				results,
				{
					name = commandName,
					result = "fail",
					message = `Command "{commandName}" was not found.`,
					intent = intent,
				} :: CommandExecutionResult
			)
			continue
		end

		local context = Commands:CreateContext(command, input, inputContext)
		local valid, message = Commands:Validate(command, context, arguments)
		if not valid then
			table.insert(
				results,
				{ name = commandName, result = "error", message = message, intent = intent } :: CommandExecutionResult
			)
			continue
		end

		local success, commandMessage = Commands:Run(command, context, arguments)
		if not success then
			table.insert(
				results,
				{ name = commandName, result = "error", message = commandMessage, intent = intent } :: CommandExecutionResult
			)
			continue
		end

		table.insert(
			results,
			{
				name = commandName,
				result = "success" :: "success",
				message = commandMessage,
				data = context.Data,
				intent = intent,
			} :: CommandExecutionResult
		)
	end

	return results
end

function Commands:Process(input, inputContext)
	local clientResults = Commands:ProcessClient(input, inputContext)

	for _, clientCommandProcessResult in clientResults do
		local clientResult, clientMessage, contextData =
			clientCommandProcessResult.result, clientCommandProcessResult.message, clientCommandProcessResult.data

		if clientResult ~= "success" then
			-- Only output fail messages if the inputContext wasn't the chat (because you can also send chat messages in chat, duh),
			-- Error messages should always be displayed.
			if clientResult == "error" or (clientResult == "fail" and inputContext ~= InputContext.Chat) then
				Output:append(
					Output.MessageType.Error,
					clientMessage or "Unexpected error occured while running command."
				)
			end
		elseif clientMessage then
			Output:append(Output.MessageType.Success, clientMessage)
		end

		if not clientCommandProcessResult.intent then
			continue
		end

		local serverResult, serverMessage =
			Commands:ProcessServer(contextData, clientCommandProcessResult.intent, inputContext)

		-- server still uses ProcessResult enum and Old System
		if serverResult ~= ProcessResult.Success then
			-- We don't check if the ProcessResult was a Fail or Error here, because it should always be an Error.
			Output:append(Output.MessageType.Error, serverMessage or "Unexpected error occured while running command.")
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
