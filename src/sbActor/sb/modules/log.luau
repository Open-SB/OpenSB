local setfenv = setfenv
local game = game
local print = print
local warn = warn
local table = table
local type = type

setfenv(1, {})

local TestService = game:GetService("TestService")

local Log = {}
Log.debugEnabled = game:GetService("RunService"):IsStudio()

function Log.setDebugEnabled(enabled: boolean)
	if type(enabled) == "boolean" then
		Log.debugEnabled = enabled
	end
end

function Log.debug(...: any)
	if Log.debugEnabled then
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
