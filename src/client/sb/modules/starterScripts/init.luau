--!strict
local setfenv = setfenv
local script = script
local task = task
local require = require
local ipairs = ipairs

setfenv(1, {})

local Modules = require(script.Parent)

local Log = Modules.require("log")

local starterScripts = script:GetChildren()
script = nil

local total, loaded = #starterScripts, 0
local scriptList: { [string]: any } = {}

Log.debug("Starting starter scripts...")
for _, starterScript in ipairs(starterScripts) do
	task.defer(function()
		scriptList[starterScript.Name] = require(starterScript:Clone())
		loaded += 1
	end)
end

while total > loaded do
	task.wait()
end

return { scriptList }
