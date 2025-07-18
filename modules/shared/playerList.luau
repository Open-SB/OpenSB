--!strict

local table = table
local ipairs = ipairs

-- Only really used for a safe PlayerRemoved (fired after they leave!!) signal (for cleanup things).

local Signal = require("@shared/signal")

local PlayerList = {}
PlayerList.Added = Signal.new()
PlayerList.Removed = Signal.new()

local Players = game:GetService("Players")
local list: { [Player]: true } = {}

function PlayerList:GetList(): { Player }
	local players = {}
	for player in list do
		table.insert(players, player)
	end

	return players
end

local function added(player: Player)
	if list[player] == true then
		return
	end

	list[player] = true
	PlayerList.Added:Fire(player)
end

local function removed(player: Player)
	if list[player] == nil then
		return
	end

	list[player] = nil
	PlayerList.Removed:Fire(player)
end

game:GetService("RunService").Heartbeat:Connect(function()
	for player in list do
		if player.Parent == Players then
			continue
		end

		removed(player)
	end

	for _, player in ipairs(Players:GetPlayers()) do
		if list[player] then
			continue
		end

		added(player)
	end
end)

Players.PlayerAdded:Connect(added) -- Fire .Added as soon as possible
-- We could connect Players.PlayerRemoving, but then the .Removed event will fire before the player has fully left

return table.freeze(PlayerList)
