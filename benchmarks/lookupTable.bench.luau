--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local N = 1000
local keys = { "A", "B", "C", "D", "E", "F" }

local lookup = {
	["A"] = "a",
	["C"] = "c",
	["E"] = "e",
}

local magic = setmetatable(table.clone(lookup), {
	__index = function(_, key)
		return key
	end,
})

return {
	ParameterGenerator = function()
		return keys[math.random(1, #keys)]
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["reference"] = function(Profiler, key)
			for _ = 1, N do
				local _ = lookup[key]
			end
		end,

		["lookup + or"] = function(Profiler, key)
			for _ = 1, N do
				local _ = lookup[key] or key
			end
		end,

		["lookup + __index"] = function(Profiler, key)
			for _ = 1, N do
				local _ = magic[key]
			end
		end,
	},
}
