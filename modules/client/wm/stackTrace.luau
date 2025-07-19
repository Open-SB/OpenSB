local table = table
local ipairs = ipairs

local SharedStackTrace = require("@shared/stackTrace")
local Functions = require("@shared/functions")
local VM = require("@client/wm/sandbox/vm")

local vmStart = VM.vmStart
local vmEnd = VM.vmEnd
local getDebugInfo = VM.getDebugInfo
local getRunning = VM.getRunning

local StackTrace = setmetatable({}, { __index = SharedStackTrace })

export type StackTrace = SharedStackTrace.StackTrace

-- Get the source of the worker manager (to work with stack traces)
local wmSource = debug.info(Functions.empty, "s")

function StackTrace.filter(stackTrace: StackTrace, running: VM.RunningInfo?): StackTrace
	local newStackTrace = {}

	local currentStack: VM.RunningInfo? = running or getRunning()
	for _, data in ipairs(stackTrace) do
		-- Check if the stack is external
		if data.source ~= wmSource then
			table.insert(newStackTrace, data)

			continue
		end

		if not currentStack then
			continue
		end

		local line = tonumber(data.line)
		if line < vmStart or line > vmEnd then
			-- If the line is before vmStart or after vmEnd, it's not a user owned stack
			continue
		end

		local vmSource, vmLine, vmName = getDebugInfo(currentStack)
		table.insert(newStackTrace, table.freeze({ source = vmSource, line = vmLine, name = vmName }))

		currentStack = currentStack.stackParent
	end

	return table.freeze(newStackTrace)
end

return StackTrace
