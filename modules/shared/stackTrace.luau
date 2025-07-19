local debug = debug
local table = table
local string = string
local ipairs = ipairs

local Functions = require("@shared/functions")

local getFunctionName = Functions.getFunctionName

local StackTrace = {}

export type StackTrace = { { source: string, line: number, name: string? } }

function StackTrace.get(level: number?): StackTrace
	local stackTrace = {}

	local offset = level or 1
	local currentLevel = 0
	while true do
		currentLevel += 1

		local func, source, line = debug.info(currentLevel + offset, "fsl")
		if not func then
			break
		end

		stackTrace[currentLevel] = table.freeze({ source = source, line = line, name = getFunctionName(func) })
	end

	return table.freeze(stackTrace)
end

function StackTrace.fromScriptContextStackTrace(stackTrace: string): StackTrace
	local traces = string.split(stackTrace, "\n")
	local numTraces = #traces - 1 -- Last trace is always "" (so we skip it)

	local newStackTrace = table.create(numTraces)
	for index = 1, numTraces do
		local source, line, name = string.match(traces[index], "^(.+), line (%d+) %- function (.+)$")
		if not name then
			source, line = string.match(traces[index], "^(.+), line (%d+)$")
		end

		newStackTrace[index] = table.freeze({ source = source, line = line, name = name })
	end

	return table.freeze(newStackTrace)
end

function StackTrace.formatScriptStackTrace(stackTrace: StackTrace): { string }
	local strs = { "Stack Begin" }
	for _, stack in ipairs(stackTrace) do
		local source, line, name = stack.source, stack.line, stack.name
		if name then
			table.insert(strs, `Script '{source}', Line {line} - function {name}`)
		else
			table.insert(strs, `Script '{source}', Line {line}`)
		end
	end

	table.insert(strs, "Stack End")
	return strs
end

return table.freeze(StackTrace)
