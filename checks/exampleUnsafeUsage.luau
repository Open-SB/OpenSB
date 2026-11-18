-- pretend this is running in a worker manager

local os = os

do
	local a = bit32
	local b = buffer
end

local function a()
	buffer.create(0) -- unsafe
end

function b()
	function c()
		buffer.create(0) -- unsafe
	end
end

local c = function()
	buffer.create(0) -- unsafe
end
