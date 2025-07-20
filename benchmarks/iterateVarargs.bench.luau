--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local N = 100

return {
	ParameterGenerator = function()
		local parameters = math.random(1, 10)
		return unpack(table.create(parameters, "value"), 1, parameters)
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["reference"] = function(Profiler, ...)
			local arr, length = { ... }, select("#", ...)
			for _ = 1, N do
				for index = 1, length do
					local _ = arr[index]
				end
			end
		end,

		["table.pack"] = function(Profiler, ...)
			for _ = 1, N do
				local arr = table.pack(...)
				local length = arr.n

				for index = 1, length do
					local _ = arr[index]
				end
			end
		end,

		["wrap + select"] = function(Profiler, ...)
			for _ = 1, N do
				local arr, length = { ... }, select("#", ...)

				for index = 1, length do
					local _ = arr[index]
				end
			end
		end,

		["select"] = function(Profiler, ...)
			for _ = 1, N do
				local length = select("#", ...)

				for index = 1, length do
					local _ = (select(index, ...))
				end
			end
		end,
	},
}
