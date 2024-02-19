local Players = game:GetService("Players")

local Network = require("server/network")
local MessageTypes = require("shared/output/messageTypes")

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

return Output
