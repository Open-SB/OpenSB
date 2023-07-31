--!strict
local setfenv = setfenv
local script = script
local task = task
local require = require
local ipairs = ipairs

setfenv(1, {})

local Modules = require(script.Parent)

local Log = Modules.require("log")

local scripts = script:GetChildren()
script = nil

local totalScripts, loadedScripts = #scripts, 0
local scriptList: { [string]: any } = {}

Log.debug("Starting starter scripts...")
for _, script in ipairs(scripts) do
	task.defer(function()
		scriptList[script.Name] = require(script:Clone())
		loadedScripts += 1
	end)
end

while totalScripts > loadedScripts do
	task.wait()
end

return { scriptList }
