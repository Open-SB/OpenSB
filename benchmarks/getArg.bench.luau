--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local parameters = 10
local N = 100

return {
	ParameterGenerator = function()
		return parameters, unpack(table.create(parameters, "value"), 1, parameters)
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["select"] = function(Profiler, parameters, ...)
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

		["wrap + index"] = function(Profiler, parameters, ...)
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

		["wrap + rawget"] = function(Profiler, parameters, ...)
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

		["variables"] = function(Profiler, parameters, ...)
			if parameters ~= 10 then
				error("Parameters ~= 10")
			end

			do
				Profiler.Begin("1")
				local _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("2")
				local _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("3")
				local _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("4")
				local _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("5")
				local _, _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("6")
				local _, _, _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("7")
				local _, _, _, _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("8")
				local _, _, _, _, _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("9")
				local _, _, _, _, _, _, _, _, _v = ...
				Profiler.End()
			end

			do
				Profiler.Begin("10")
				local _, _, _, _, _, _, _, _, _, _v = ...
				Profiler.End()
			end
		end,
	},
}
