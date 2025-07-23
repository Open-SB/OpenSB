--[[
This file is for use by Benchmarker (https://boatbomber.itch.io/benchmarker)

|WARNING| THIS RUNS IN YOUR REAL ENVIRONMENT. |WARNING|
--]]

return {
	ParameterGenerator = function()
		local n = 1000
		local t = table.create(n, "value")
		return function()
			return unpack(t, 1, n)
		end
	end,

	BeforeAll = function() end,
	AfterAll = function() end,
	BeforeEach = function() end,
	AfterEach = function() end,

	Functions = {
		["table.pack + unpack"] = function(Profiler, func)
			Profiler.Begin("pack")
			local packed = table.pack(func())
			Profiler.End()

			-- hook

			Profiler.Begin("unpack")
			unpack(packed, 1, packed.n)
			Profiler.End()
		end,

		["uncached variadic"] = function(Profiler, func)
			Profiler.Begin("pack");
			(function(...)
				Profiler.End()

				-- hook

				Profiler.Begin("unpack")
				return ...
			end)(func())
			Profiler.End()
		end,

		["cached variadic"] = function(Profiler, func)
			Profiler.Begin("pack");
			(function(_Profiler, ...)
				-- Not using mutable upvalues outside of this closure allows it to be cached (meaning a new function object doesn't get created each time it's declared like this).
				_Profiler.End()

				-- hook

				_Profiler.Begin("unpack")
				return ...
			end)(Profiler, func())
			Profiler.End()
		end,
	},
}
