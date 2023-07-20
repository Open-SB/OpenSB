local shared, _G = shared, _G
local actor = script.Parent.Parent
script:Destroy()

setmetatable(shared, {
	__metatable = "The metatable is locked",
	__call = function(_t, topic, ...)
		-- do magic
	end,
})
setmetatable(_G, {
	__metatable = "The metatable is locked",
})

actor:SendMessage("scriptManager::load")
