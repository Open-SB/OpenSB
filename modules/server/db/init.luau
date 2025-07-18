-- This doesn't persist between servers and is just an example.
local datas = {}
local function getUserData(userId: number)
	local data = datas[userId]
	if data then
		return data
	end

	data = {
		scripts = {},
	}
	datas[userId] = data

	return data
end

local PlayerList = require("@shared/playerList")
PlayerList.Removed:Connect(function(player)
	datas[player.UserId] = nil
end)

type sourceType = "source" | "http"

local DB = {}

function DB:GetScripts(userId: number): { string }
	local scripts = {}
	for name in getUserData(userId).scripts do
		table.insert(scripts, name)
	end

	return scripts
end

function DB:GetScript(userId: number, scriptName: string): { sourceType: sourceType, source: string }?
	local script = getUserData(userId).scripts[scriptName]
	if not script then
		return
	end

	return {
		sourceType = script[1],
		source = script[2],
	}
end

function DB:SaveScript(userId: number, scriptName: string, sourceType: sourceType, source: string)
	getUserData(userId).scripts[scriptName] = { sourceType, source }
end

function DB:RemoveScript(userId: number, scriptName: string)
	getUserData(userId).scripts[scriptName] = nil
end

return table.freeze(DB)
