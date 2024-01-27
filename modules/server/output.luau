local Network = require("server/network")
local MessageTypes = require("shared/output/messageTypes")

local Output = {}
Output.MessageType = MessageTypes

function Output:append(player, messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Network:FireClient(player, "output::append", messageType, message, dateTime)
end

return Output
