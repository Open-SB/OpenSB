--!strict

-- Only really used for a safe PlayerRemoved (fired after they leave!!) signal (for cleanup things).

local Signal = require("@shared/signal")

local PlayerList = {}
PlayerList.Added = Signal.new()
PlayerList.Removed = Signal.new()

local Players = game:GetService("Players")
local list: { [Player]: true } = {}

local function added(player: Player)
	list[player] = true
	PlayerList.Added:Fire(player)
end

local function removed(player: Player)
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

return table.freeze(PlayerList)
