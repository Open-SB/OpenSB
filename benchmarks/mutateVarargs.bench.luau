--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local parameters = 10
local N = 2000

return {
	ParameterGenerator = function()
		return unpack(table.create(parameters, 1), 1, parameters)
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["table.pack"] = function(Profiler, ...)
			for _ = 1, N do
				local arr = table.pack(...)
				local length = arr.n

				for index = 1, length do
					arr[index] = arr[index] + 1
				end

				unpack(arr, 1, length)
			end
		end,

		["wrap + select"] = function(Profiler, ...)
			for _ = 1, N do
				local arr, length = { ... }, select("#", ...)

				for index = 1, length do
					arr[index] = arr[index] + 1
				end

				unpack(arr, 1, length)
			end
		end,

		["select"] = function(Profiler, ...)
			for _ = 1, N do
				local length = select("#", ...)
				local arr = table.create(length)

				for index = 1, length do
					arr[index] = (select(index, ...)) + 1
				end

				unpack(arr, 1, length)
			end
		end,
	},
}
