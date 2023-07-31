--!strict
local __start = os.clock()

-- Localize variables and remove environment for security
local game = game
local coroutine = coroutine
local task = task
local script = script
local setfenv = setfenv
local math = math
local os = os
local next = next
local table = table
local require = require
local type = type

-- These are replaced later
local _print = print
local _warn = warn

setfenv(1, {})

-- Wait for all descendants
do
	local descendants = script:GetAttribute("_descendants")
	script:SetAttribute("_descendants", nil)

	if type(descendants) == "number" then -- May have been tampered with, and if thats the case I think it's the best to skip this, we may want to add a timeout aswell
		while descendants > #script:GetDescendants() do
			script.DescendantAdded:Wait()
		end
	end
end

local networkAttribute = { next(script:GetAttributes()) }
local Log = require(script:WaitForChild("modules"):WaitForChild("log"))[1]

-- Fetch assets and destroy script
Log.debug("Fetching assets")

local sbActor = script.Parent

local modules = script:WaitForChild("modules"):Clone()

do
	local attributeChanged = sbActor:GetAttributeChangedSignal("canDestroy")
	while not sbActor:GetAttribute("canDestroy") do
		attributeChanged:Wait()
	end
end

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			sbActor:Destroy()
			script:Destroy()
			script = nil

			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

-- Services and modules
Log.debug("Loading modules")

local Modules = require(modules)
local Network = Modules.require("network")

Network.init(networkAttribute)

-- Finalize
Log.debug("Finalizing...")

Modules.require("starterScripts"):Start()

Modules.waitForModulesToLoad()
Modules:Lock()
modules:Destroy()

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms`)
