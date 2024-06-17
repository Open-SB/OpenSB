if script:GetActor() ~= nil then
	-- We check if the script is inside an actor and throw an error if so. If we didn't do this then someone would be able to log the moduleScriptHostKey that is sent via shared(), as the shared global is different in different actors (Luau VM's).
	return error("SB scripts cannot be ran under actors.", 0)
end

local func, err = shared(_G.moduleScriptHostKey, script)
if err then
	return task.spawn(error, err) -- Spawning the error function "removes" the error stack messages (excluding the "Stack Begin" and "Stack End").
end

setfenv(1, getfenv(func))
return func()
