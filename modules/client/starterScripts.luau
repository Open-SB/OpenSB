local Log = require("shared/log")
local Assets = require("shared/assets")

local scripts = Assets:get("starterScripts"):GetChildren()
local starterScripts = {}

function starterScripts:Init()
	Log.debug("Starting starter scripts...")
	for _, starterScript in ipairs(scripts) do
		task.defer(require, starterScript:Clone())
	end
end

return starterScripts
