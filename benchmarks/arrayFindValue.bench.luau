--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local N = 10000
local value = "d"

return {
	ParameterGenerator = function()
		return table.freeze({ "a", "b", "c", "d", "e" })
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["table.find"] = function(Profiler, arr)
			for _ = 1, N do
				table.find(arr, value)
			end
		end,

		["manual"] = function(Profiler, arr)
			for _ = 1, N do
				for _, v in ipairs(arr) do
					if v == value then
						break
					end
				end
			end
		end,
	},
}
