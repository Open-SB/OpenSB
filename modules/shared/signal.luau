local Signal = {}
Signal.__index = Signal

function Signal.new()
	local self = setmetatable({}, Signal)
	self._bindable = Instance.new("BindableEvent")
	self._argMap = {}

	-- Events connected first always fire last
	self._bindable.Event:Connect(function(key)
		self._argMap[key] = nil
	end)

	return self
end

function Signal:Destroy()
	if self._bindable then
		self._bindable:Destroy()
		self._bindable = nil
	end

	setmetatable(self, nil)
end

function Signal:Fire(...)
	local key = math.random()
	self._argMap[key] = table.pack(...)
	self._bindable:Fire(key)
end

function Signal:Connect(callback)
	return self._bindable.Event:Connect(function(key)
		local args = self._argMap[key]
		if args then
			callback(table.unpack(args, 1, args.n))
		end
	end)
end

function Signal:Once(callback)
	return self._bindable.Event:Once(function(key)
		local args = self._argMap[key]
		if args then
			callback(table.unpack(args, 1, args.n))
		end
	end)
end

function Signal:Wait()
	local key = self._bindable.Event:Wait()
	local args = self._argMap[key]

	if args then
		return table.unpack(args, 1, args.n)
	end
end

return Signal
