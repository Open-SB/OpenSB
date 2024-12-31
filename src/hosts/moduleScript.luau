local func, arguments, unwrap, err = shared(_G.moduleScriptHostKey, script)
if err then
	return task.spawn(error, err) -- Spawning the error function "removes" the error stack messages (excluding the "Stack Begin" and "Stack End").
end

-- Localize the setfenv function because we change the environment.
local setfenv = setfenv

local env = getfenv(func)
setfenv(0, env)
setfenv(1, env)

-- TODO: Fix this adding an extra line to the traceback (task.spawn + coroutine.yield + custom require / manually filtering it out from functions)
return unwrap(func(unpack(arguments, 1, arguments.n)))
