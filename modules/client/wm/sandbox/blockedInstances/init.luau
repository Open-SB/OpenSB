local ipairs = ipairs
local table = table

local lookup = {}
local list = table.freeze(require("@self/list.yaml"))
for _, class in ipairs(list) do
	lookup[class] = true
end

return table.freeze(lookup)
