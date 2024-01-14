local TestService = game:GetService("TestService")
local prefix = game:GetService("RunService"):IsClient() and "[SB Client]" or "[SB]"

local Log = {}

function Log.debug(...: any)
	if _G.DEV then
		TestService:Message(prefix .. " " .. table.concat({ ... }, " "))
	end
end

function Log.print(...: any)
	print(prefix, ...)
end

function Log.warn(...: any)
	warn(prefix, ...)
end

return Log
