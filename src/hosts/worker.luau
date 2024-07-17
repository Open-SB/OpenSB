script.Parent:Destroy() -- Lock parent

local func, arguments, track, err = shared(_G.moduleScriptHostKey, script)
if err then
	return task.spawn(error, err) -- Spawning the error function "removes" the error stack messages (excluding the "Stack Begin" and "Stack End").
end

-- Localize the setfenv function because we change the environment.
local setfenv = setfenv
local spawn = task.spawn

local env = getfenv(func)
setfenv(0, env)
setfenv(1, env)

track(spawn(func, unpack(arguments, 1, arguments.n)))
return nil
