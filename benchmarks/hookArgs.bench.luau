--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

local N = 100

return {
	ParameterGenerator = function()
		return function()
			return "value1", "value2", "value3"
		end
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["variables"] = function(Profiler, func)
			for _ = 1, N do
				local a1, a2, a3 = func()

				local v = 1
				local _ = v

				-- hook

				local _1, _2, _3 = a1, a2, a3
			end
		end,

		["uncached variadic"] = function(Profiler, func)
			for _ = 1, N do
				local v = 1
				local _1, _2, _3 = (function(...)
					local _ = v

					-- hook

					return ...
				end)(func())
			end
		end,

		["cached variadic"] = function(Profiler, func)
			for _ = 1, N do
				local _1, _2, _3 = (function(...)
					-- Not using mutable upvalues outside of this closure allows it to be cached (meaning a new function object doesn't get created each time it's declared like this).
					local v = 1
					local _ = v

					-- hook

					return ...
				end)(func())
			end
		end,
	},
}
