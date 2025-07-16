local Log = require("shared/log")
local Functions = require("shared/functions")

local ManagerCommunication = require("shared/wm/communication")

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

		local Manager = ManagerCommunication.new(send, recieve, invoke, invoked)
		WorkerManagers[index] = Manager

		manager.Name ..= `{index}@{math.random()}` -- We give them a random name to help filter out sb stack traces from other code
		manager.Parent = parent

		return Manager
	end

	WorkerManagers.main = createManager(root, 0)
	for index = 1, _G.workerThreads do
		local actor = Instance.new("Actor")
		createManager(actor, index)
		actor.Parent = root
	end

	table.freeze(WorkerManagers)
end

function WorkerManagers:ready()
	-- Sends with awaitReceiver set to true, meaning it will use the normal :Send() function (which waits for the receiving end to be fully ready).
	-- The other side does not send with this set to true, as our side will always be ready to receive the "ready" event.

	WorkerManagers.main:ready(true)
	for _, Manager in ipairs(WorkerManagers) do
		Manager:ready(true)
	end
end

function WorkerManagers:on(topic: string, callback: (any...) -> never)
	WorkerManagers.main:on(topic, callback)
	for _, Manager in ipairs(WorkerManagers) do
		Manager:on(topic, callback)
	end
end

function WorkerManagers:onInvoke(topic: string, callback: (any...) -> any...)
	WorkerManagers.main:onInvoke(topic, callback)
	for _, Manager in ipairs(WorkerManagers) do
		Manager:onInvoke(topic, callback)
	end
end

function WorkerManagers:Send(topic: string, ...)
	WorkerManagers.main:Send(topic, ...)
	for _, Manager in ipairs(WorkerManagers) do
		Manager:Send(topic, ...)
	end
end

return WorkerManagers
