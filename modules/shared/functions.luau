-- Maybe this should be rewritten to have each function in it's own file?
local string = string
local math = math
local game = game
local coroutine = coroutine
local debug = debug
local table = table

local Functions = {}

function Functions.empty() end

function Functions.randomString(length: number): string
	local str = ""

	for _ = 1, length or 32 do
		str = str .. string.char(math.random(0, 127))
	end

	return str
end

Functions.randomInstanceName = math.random

-- This function makes the string "null terminated" (stops before a null character)
function Functions.nullTerminate(str: string): string
	local nullIndex = string.find(str, "\0", 1, true)
	if nullIndex then
		return string.sub(str, 1, nullIndex - 1)
	end

	return str
end

function Functions.toCString(value: any): string
	return Functions.nullTerminate(tostring(value))
end

function Functions.toCDouble(value: any): number?
	local datatype = type(value)
	if datatype == "number" then
		return value
	elseif datatype == "boolean" then
		return if value then 1 else 0
	end

	return tonumber(value)
end

function Functions.getInstanceName(instance: Instance?): string
	return if instance ~= nil then instance.Name else "NULL"
end

function Functions.getFunctionName(func: () -> ()): string?
	local name = debug.info(func, "n")
	return if name and #name == 0 then nil else name
end

do
	local indexThread = coroutine.create(function()
		return game[true]
	end)
	local newindexThread = coroutine.create(function()
		game[true] = true
	end)

	-- Coroutine.resume doesn't omit errors unlike task.spawn
	coroutine.resume(indexThread)
	coroutine.resume(newindexThread)

	Functions.indexInstance = debug.info(indexThread, 0, "f")
	Functions.newindexInstance = debug.info(newindexThread, 0, "f")
end

function Functions.formatPlayerName(player: Player): string
	if player.DisplayName == player.Name then
		return player.DisplayName
	end

	return `{player.DisplayName} (@{player.Name})`
end

function Functions.getServerType(): "StandardServer" | "ReservedServer" | "VIPServer"
	if game.PrivateServerId ~= "" then
		if game.PrivateServerOwnerId ~= 0 then
			return "VIPServer"
		else
			return "ReservedServer"
		end
	else
		return "StandardServer"
	end
end

return table.freeze(Functions)
