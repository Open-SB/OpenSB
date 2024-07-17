if script:GetActor() ~= nil then
	-- We check if the script is inside an actor and throw an error if so. If we didn't do this then someone would be able to log the localScriptHostKey that is sent via shared(), as the shared global is different in different actors (Luau VM's).
	return error("SB scripts cannot be ran under actors.", 0)
end

local func, arguments, err = shared(_G.localScriptHostKey, script)
if err then
	return task.spawn(error, err) -- Spawning the error function "removes" the error stack messages (excluding the "Stack Begin" and "Stack End").
end

-- Localize the setfenv and spawn functions because we change the environment.
local setfenv = setfenv
local spawn = task.spawn

local env = getfenv(func)
setfenv(0, env)
setfenv(1, env)

-- Spawn the function to not count towards the error stack.
spawn(func, unpack(arguments, 1, arguments.n))
