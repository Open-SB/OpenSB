-- Maybe this should be rewritten to have each function in it's own file?
local string = string
local math = math
local game = game
local coroutine = coroutine
local debug = debug
local table = table

local Functions = {}

function Functions.empty() end

function Functions.randomString(length)
	local str = ""

	for _ = 1, length or 32 do
		str = str .. string.char(math.random(0, 127))
	end

	return str
end

Functions.randomInstanceName = math.random

-- This function makes the string "null terminated" (stops before a null character)
function Functions.toCString(str: string)
	local nullIndex = string.find(str, "\0", 1, true)
	if nullIndex then
		return string.sub(str, 1, nullIndex - 1)
	end

	return str
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

return table.freeze(Functions)
