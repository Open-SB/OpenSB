local Functions = require("@shared/functions")

local getInstanceName = Functions.getInstanceName
local getFunctionName = Functions.getFunctionName

local Errors = {}

function Errors.cannotAccess(instance: Instance, capability: string?): string
	if capability then
		return `The current thread cannot access '{getInstanceName(instance)}' (lacking capability {capability})`
	else
		return `The current thread cannot access '{getInstanceName(instance)}'`
	end
end

function Errors.cannotCall(func: () -> () | string, capability: string?): string
	local name = if type(func) == "string" then func else (getFunctionName(func) or "")
	if capability then
		return `The current thread cannot call '{name}' (lacking capability {capability})`
	else
		return `The current thread cannot call '{name}'`
	end
end

function Errors.lockedParent(instance: Instance): string
	return `The Parent property of {getInstanceName(instance)} is locked`
end

function Errors.lockedParentSet(instance: Instance, newParent: Instance?): string
	return `The Parent property of {getInstanceName(instance)} is locked, current parent: {getInstanceName(
		instance.Parent
	)}, new parent: {getInstanceName(newParent)}`
end

function Errors.parentToWriteProtected(parent: Instance): string
	return `Cannot set Parent property to {getInstanceName(parent)}`
end

function Errors.createBlockedClass(class: string): string
	return `Unable to create an Instance of type {class}`
end

function Errors.connectNonFunction(): string
	return `Attempt to connect failed: Passed value is not a function`
end

return table.freeze(Errors)
