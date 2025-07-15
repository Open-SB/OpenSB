--!strict

-- number = 0 | 1 | 2
--[[
each further level implies the last
0 - remove protection [ allow reads & writes & descendant inserts ]
1 - remove protection & no writing [ allow reads ]
2 - remove protection & write protection & read protection [ ghost ]
]]

local Functions = require("shared/functions")

local protectedInstances: { [Instance]: number? } = {}

local protectedClasses: { [string]: number? } = {}
do
	local yaml = table.freeze(require("./classes.yaml"))

	for _, class in ipairs(yaml.remove_protected) do
		protectedClasses[class] = 0
	end

	for _, class in ipairs(yaml.write_protected) do
		protectedClasses[class] = 1
	end
	
	for _, class in ipairs(yaml.read_protected) do
		protectedClasses[class] = 2
	end
end

table.freeze(protectedClasses)

local function isRemoveProtected(instance: Instance)
	return ((protectedInstances[instance] or protectedClasses[instance.ClassName]) or -1) >= 0
end

local function isWriteProtected(instance: Instance)
	return ((protectedInstances[instance] or protectedClasses[instance.ClassName]) or -1) >= 1
end

local function isReadProtected(instance: Instance)
	return ((protectedInstances[instance] or protectedClasses[instance.ClassName]) or -1) == 2
end

type OutsideLevel = "remove" | "write" | "read"

local function isProtected(instance: Instance, level: OutsideLevel)
	if level == "remove" then
		return isRemoveProtected(instance)
	elseif level == "write" then
		return isWriteProtected(instance)
	elseif level == "read" then
		return isReadProtected(instance)
	else
		error(`got unknown level: {level}`, 2)
	end
end

local function protect(instance: Instance, level: OutsideLevel)
	if level == "remove" then
		protectedInstances[instance] = 0
	elseif level == "write" then
		protectedInstances[instance] = 1
	elseif level == "read" then
		protectedInstances[instance] = 2
	else
		error(`got unknown level: {level}`, 2)
	end
end

local function unprotect(instance: Instance)
	protectedInstances[instance] = nil
end

-- setup initial services
for _, service in { game:GetService("TextChatService") } do
	for _, descendant in service:GetDescendants() do
		protectedInstances[descendant] = 0
	end
end

return table.freeze({
	isRemoveProtected = isRemoveProtected,
	isWriteProtected = isWriteProtected,
	isReadProtected = isReadProtected,
	isProtected = isProtected,
	add = protect,
	remove = unprotect,
	protectedInstances = protectedInstances,
	protectedClasses = protectedClasses,
})
