local tostring = tostring
local math = math
local string = string

local Functions = {}

function Functions.empty() end

function Functions.randomString(length)
	local str = ""

	for _ = 1, length or 32 do
		str = str .. string.char(math.random(0, 127))
	end

	return str
end

function Functions.randomInstanceName()
	return tostring(math.random())
end

return Functions
