--!strict

local WorkerManagers = require("@shared/workerManagers")

local function protect(instance: Instance, level: "remove" | "write" | "read")
	WorkerManagers:Send("protect", instance, level)
end

local function unprotect(instance: Instance)
	WorkerManagers:Send("unprotect", instance)
end

return table.freeze({
	add = protect,
	remove = unprotect,
})
