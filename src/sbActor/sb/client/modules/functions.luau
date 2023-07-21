--!strict
local setfenv = setfenv

setfenv(1, {})

local Functions = {}

function Functions.empty() end

return { Functions }
