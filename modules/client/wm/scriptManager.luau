local setmetatable = setmetatable
local shared = shared
local rawequal = rawequal
local error = error

local Module = {}

function Module:Init()
	setmetatable(shared, {
		__metatable = "The metatable is locked",
		__call = function(_, key, hostScript)
			if not rawequal(key, _G.localScriptHostKey) then -- Use rawequal to bypass potential __eq metamethods
				return error("invalid key", 2)
			end

			return function() end
		end,
	})
end

return Module
