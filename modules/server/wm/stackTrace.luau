local table = table
local ipairs = ipairs

local SharedStackTrace = require("@shared/stackTrace")
local Functions = require("@shared/functions")

local StackTrace = setmetatable({}, { __index = SharedStackTrace })

export type StackTrace = SharedStackTrace.StackTrace

-- Get the source of the worker manager (to filter out stack traces)
local wmSource = debug.info(Functions.empty, "s")

function StackTrace.filter(stackTrace: StackTrace): StackTrace
	local newStackTrace = {}
	for _, data in ipairs(stackTrace) do
		if data.source == wmSource then
			continue
		end

		table.insert(newStackTrace, data)
	end

	return table.freeze(newStackTrace)
end

return StackTrace
