local protectedServices = table.freeze({
	[game:GetService("TextChatService")] = true,
})

local function getProtectedServiceFromInstance(instance: Instance)
	for service in protectedServices do
		if instance:IsDescendantOf(service) then
			return service
		end
	end

	return nil
end

local function isProtected(instance: Instance)
	return protectedServices[instance] or (getProtectedServiceFromInstance(instance) ~= nil)
end

return table.freeze({
	isProtected = isProtected,
	getProtectedServiceFromInstance = getProtectedServiceFromInstance,
	protectedServices = protectedServices,
})
