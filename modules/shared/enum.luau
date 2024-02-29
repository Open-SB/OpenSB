return function(enumItems)
	local enum = {}
	for index, name in ipairs(enumItems) do
		enum[name] = index - 1
		enum[index - 1] = name
	end

	if _G.DEV then
		setmetatable(enum, {
			__index = function(_, index)
				return error(`"{index}" is not a valid enum item.`, 2)
			end,
		})
	end

	return table.freeze(enum)
end
