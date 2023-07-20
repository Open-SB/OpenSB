--!strict
local setfenv = setfenv
local tostring = tostring
local math = math

setfenv(1, {})

local Functions = {}

function Functions.randomInstanceName()
	return tostring(math.random())
end

return { Functions }
