--!strict

-- number = 0 | 1 | 2
--[[
each further level implies the last
0 - remove protection [ allow reads & writes & descendant inserts ]
1 - remove protection & no writing [ allow reads ]
2 - remove protection & write protection & read protection [ ghost ]
]]

local ManagerCommunication = require("shared/wm/communication")

local protectedInstances: { [Instance]: number } = {}
local protectedClasses: { [string]: number } = {}

do
	local yaml = table.freeze(require("./classes.yaml"))
	local function read(arr: { string }, level: number)
		for _, class in ipairs(arr) do
			protectedClasses[class] = level
		end
	end

	read(yaml.remove_protected, 0)
	read(yaml.write_protected, 1)
	read(yaml.read_protected, 2)

	table.freeze(protectedClasses)
end

local function getLevel(instance: Instance)
	return (protectedInstances[instance] or protectedClasses[instance.ClassName]) or -1
end

local function isRemoveProtected(instance: Instance)
	return getLevel(instance) >= 0
end

local function isWriteProtected(instance: Instance)
	return getLevel(instance) >= 1
end

local function isReadProtected(instance: Instance)
	return getLevel(instance) == 2
end

type Level = "remove" | "write" | "read"

local function isProtected(instance: Instance, level: Level)
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

local function protect(instance: Instance, level: Level)
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

local function getProtection(instance: Instance): Level?
	local level = getLevel(instance)
	if level == -1 then
		return nil
	elseif level == 0 then
		return "remove"
	elseif level == 1 then
		return "write"
	elseif level == 2 then
		return "read"
	else
		error(`got unknown level: {level}`)
	end
end

-- setup initial services
for _, service in { game:GetService("TextChatService") } do
	for _, descendant in service:GetDescendants() do
		protectedInstances[descendant] = 0
	end
end

-- listen for requests on the backend
ManagerCommunication:on("protect", protect)
ManagerCommunication:on("unprotect", unprotect)

return table.freeze({
	isRemoveProtected = isRemoveProtected,
	isWriteProtected = isWriteProtected,
	isReadProtected = isReadProtected,
	isProtected = isProtected,

	add = protect,
	remove = unprotect,
	get = getProtection,
})
