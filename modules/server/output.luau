local Players = game:GetService("Players")

local Network = require("@server/network")
local MessageTypes = require("@shared/output/messageTypes")
local Functions = require("@shared/functions")

local Output = {}
Output.MessageType = MessageTypes

function Output:appendTo(player, messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Network:FireClient(player, "output::append", messageType, message, dateTime)
end

function Output:appendToAll(messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Network:FireAllClients("output::append", messageType, message, dateTime)
end

function Output:appendToOthers(excludedPlayer, messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	local players = Players:GetPlayers()
	local index = table.find(players, excludedPlayer)
	if index then
		table.remove(players, index)
	end

	for _, player in players do
		Network:FireClient(player, "output::append", messageType, message, dateTime)
	end
end

function Output:appendWithIdTo(player, messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	local id = Functions.randomString()
	Network:FireClient(player, "output::appendWithId", messageType, message, dateTime, id)

	return id
end

function Output:editFrom(player, id, messageType, message, dateTime)
	assert(messageType, "No messageType given.")
	assert(MessageTypes[messageType], "Invalid message type.")
	assert(message, "No message given.")

	Network:FireClient(player, "output::edit", id, messageType, message, dateTime)
end

function Output:dropIdFrom(player, id)
	Network:FireClient(player, "output::dropId", id)
end

return Output
