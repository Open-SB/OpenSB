local task = task
local require = require
local ipairs = ipairs

local Log = require("shared/log")

local scripts = script:WaitForChild("starterScripts"):Clone():GetChildren()
local starterScripts = {}

function starterScripts:Init()
	Log.debug("Starting starter scripts...")
	for _, starterScript in ipairs(scripts) do
		task.defer(require, starterScript:Clone())
	end
end

return starterScripts
