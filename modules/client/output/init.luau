local Network = require("client/network")
local MessageTypes = require("shared/output/messageTypes")
local Signal = require("shared/signal")

local MessageTypeColors = require("./colors")

local Output = {}
Output.MessageType = MessageTypes
Output.MessageOut = Signal.new()

function Output:append(messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Output.MessageOut:Fire(dateTime or DateTime.now(), message, MessageTypeColors[messageType])
end

Network:RegisterEvent("output::append", function(...)
	Output:append(...)
end)

return Output
