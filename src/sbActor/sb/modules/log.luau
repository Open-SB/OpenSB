local setfenv = setfenv
local game = game
local print = print
local warn = warn
local table = table

setfenv(1, {})

local TestService = game:GetService("TestService")

local Log = {}
local debugEnabled = game:GetService("RunService"):IsStudio()

function Log.setDebugEnabled(enabled: boolean)
	debugEnabled = enabled
end

function Log.debug(...: any)
	if debugEnabled then
		TestService:Message("[SB] " .. table.concat({ ... }, " "))
	end
end

function Log.print(...: any)
	print("[SB]", ...)
end

function Log.warn(...: any)
	warn("[SB]", ...)
end

return { Log }
