local Log = require("shared/log")
local Functions = require("shared/functions")

local MangerCommunication = require("./communication")

local WorkerManagers = {}

function WorkerManagers:Init(root, managerName)
	Log.debug("Creating WorkerManagers...")

	-- Messy but whatever
	local managerTemplate = root:WaitForChild(managerName)
	if managerTemplate.ClassName == "ModuleScript" then
		managerTemplate:WaitForChild("start")
	end

	task.defer(game.Destroy, managerTemplate) -- Destroy old refrence, after we clone it.
	managerTemplate = managerTemplate:Clone()

	if managerTemplate.ClassName == "ModuleScript" then
		managerTemplate:WaitForChild("start").Enabled = true
	else
		managerTemplate.Enabled = true
	end

	local function createManager(parent, index)
		local manager = managerTemplate:Clone()
		local communicationExchange = Instance.new("BindableFunction")
		local send, recieve, invoke, invoked =
			Instance.new("BindableEvent"),
			Instance.new("BindableEvent"),
			Instance.new("BindableFunction"),
			Instance.new("BindableFunction")

		send.Name = Functions.randomInstanceName()
		recieve.Name = Functions.randomInstanceName()
		invoke.Name = Functions.randomInstanceName()
		invoked.Name = Functions.randomInstanceName()

		-- Secure (ish) exchange (atleast can't be obtained by other scripts).
		communicationExchange.OnInvoke = function()
			communicationExchange.OnInvoke = Functions.empty
			communicationExchange:Destroy()

			Log.debug(`Exchanged communication bindables with {managerName}{index}.`)
			return recieve, send, invoked, invoke -- Reversed on the recieveing end
		end

		communicationExchange.Name = Functions.randomInstanceName()
		communicationExchange.Parent = manager

		local Manager = MangerCommunication.new(send, recieve, invoke, invoked)
		WorkerManagers[index] = Manager

		manager.Name ..= index
		manager.Parent = parent

		return Manager
	end

	WorkerManagers.main = createManager(root, 0)
	for index = 1, _G.workerThreads - 1 do
		local actor = Instance.new("Actor")
		createManager(actor, index)
		actor.Parent = root
	end

	table.freeze(WorkerManagers)
end

return WorkerManagers
