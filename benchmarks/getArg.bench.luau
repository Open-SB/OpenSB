--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local parameters = 10
local N = 500

return {
	ParameterGenerator = function()
		return unpack(table.create(parameters, "value"), 1, parameters)
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["select"] = function(Profiler, ...)
			local function getArg(index, ...)
				return (select(index, ...))
			end

			for param = 1, parameters do
				Profiler.Begin(tostring(param))

				for _ = 1, N do
					getArg(param, ...)
				end

				Profiler.End()
			end
		end,

		["index"] = function(Profiler, ...)
			local function getArg(index, ...)
				return ({ ... })[index]
			end

			for param = 1, parameters do
				Profiler.Begin(tostring(param))

				for _ = 1, N do
					getArg(param, ...)
				end

				Profiler.End()
			end
		end,

		["rawget"] = function(Profiler, ...)
			local function getArg(index, ...)
				return rawget({ ... }, index)
			end

			for param = 1, parameters do
				Profiler.Begin(tostring(param))

				for _ = 1, N do
					getArg(param, ...)
				end

				Profiler.End()
			end
		end,
	},
}
