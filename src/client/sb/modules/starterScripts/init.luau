--!strict
local setfenv = setfenv
local script = script
local task = task
local require = require

setfenv(1, {})

local Modules = require(script.Parent)

local Log = Modules.require("log")

local scripts: { [string]: Instance } = {
	PlayerModule = script:WaitForChild("PlayerModule"):Clone(),
	RbxCharacterSounds = script:WaitForChild("RbxCharacterSounds"):Clone(),
}
script = nil

local StarterScripts = {}

function StarterScripts:Start()
	Log.debug("Starting starter scripts...")

	for _, module in scripts do
		task.defer(require, module)
	end
end

return { StarterScripts }
