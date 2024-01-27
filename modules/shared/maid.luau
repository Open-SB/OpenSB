local Maid = {}

function Maid.new()
	return setmetatable({
		_tasks = {},
	}, Maid)
end

local function clean(job)
	if type(job) == "function" then
		job()
	elseif type(job) == "thread" then
		local cancelled
		if coroutine.running() ~= job then
			cancelled = pcall(task.cancel, job)
		end

		if not cancelled then
			task.defer(task.cancel, job)
		end
	elseif typeof(job) == "RBXScriptConnection" then
		job:Disconnect()
	elseif job.Destroy then
		job:Destroy()
	end
end
Maid.clean = clean

function Maid:__index(index)
	return Maid[index] or self._tasks[index]
end

function Maid:__newindex(index, newTask)
	assert(not Maid[index], `Cannot use {index} as a Maid key.`)

	local tasks = self._tasks
	local oldTask = tasks[index]

	if oldTask == newTask then
		return
	end

	tasks[index] = newTask
	if oldTask then
		clean(oldTask)
	end
end

function Maid:Add(task)
	assert(task, "Task cannot be false or nil.")

	local tasks = self._tasks
	tasks[#tasks + 1] = task

	return task
end

function Maid:GiveTask(task)
	assert(task, "Task cannot be false or nil.")

	local tasks = self._tasks
	local taskId = #tasks + 1
	tasks[taskId] = task

	return taskId
end

function Maid:DoCleaning()
	local tasks = self._tasks

	for index, job in tasks do
		if typeof(job) == "RBXScriptConnection" then
			tasks[index] = nil
			job:Disconnect()
		end
	end

	local index, job = next(tasks)
	while job ~= nil do
		tasks[index] = nil
		clean(job)

		index, job = next(tasks)
	end
end
Maid.Destroy = Maid.DoCleaning

return Maid
