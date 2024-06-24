local Network = require("client/network")
local MessageTypes = require("shared/output/messageTypes")
local Signal = require("shared/signal")
local Functions = require("shared/functions")

local Output = {}
Output.MessageType = MessageTypes
Output.MessageOut = Signal.new()
Output.MessageIdDropped = Signal.new()

function Output:append(messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Output.MessageOut:Fire(nil, dateTime or DateTime.now(), message, messageType)
end

function Output:appendWithId(messageType, message, dateTime, id)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	id = id or Functions.randomString()
	Output.MessageOut:Fire(id, dateTime or DateTime.now(), message, messageType)

	return id
end

function Output:edit(id, messageType, message, dateTime)
	assert(id, "No message id given.")
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Output.MessageOut:Fire(id, dateTime or DateTime.now(), message, messageType)
end

function Output:dropId(id)
	assert(id, "No message id given.")

	Output.MessageIdDropped:Fire(id)
end

Network:RegisterEvent("output::append", function(...)
	Output:append(...)
end)

Network:RegisterEvent("output::appendWithId", function(...)
	Output:appendWithId(...)
end)

Network:RegisterEvent("output::edit", function(...)
	Output:edit(...)
end)

Network:RegisterEvent("output::dropId", function(...)
	Output:dropId(...)
end)

return Output
