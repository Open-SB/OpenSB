local table = table
local print = print
local warn = warn
local error = error

local TestService = game:GetService("TestService")
local prefix

local Log = {}

function Log:SetPrefix(_prefix)
	if prefix then
		return error("Prefix is already set.", 2)
	end

	prefix = _prefix
end

function Log.debug(...: any)
	if _G.debugging then
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
