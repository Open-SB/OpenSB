--!strict
local setfenv = setfenv
local string = string
local math = math

setfenv(1, {})

local Functions = {}

function Functions.empty() end

function Functions.randomString(length)
	local str = ""

	for _ = 1, length or 32 do
		str = str .. string.char(math.random(0, 127))
	end

	return str
end

return { Functions }
