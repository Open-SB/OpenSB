local function applyProperties(instance, properties)
	for key, value in properties do
		if type(key) == "number" and typeof(value) == "Instance" then
			value.Parent = instance

			continue
		end

		if type(value) == "table" then
			applyProperties(instance, value)

			continue
		end

		if typeof(instance[key]) == "RBXScriptSignal" then
			instance[key]:Connect(value)

			continue
		end

		instance[key] = value
	end
end

return function(class)
	return function(properties)
		-- We should set Parent last.
		local parent = properties.Parent
		properties.Parent = nil

		local instance = Instance.new(class)
		applyProperties(instance, properties)
		instance.Parent = parent

		return instance
	end
end
