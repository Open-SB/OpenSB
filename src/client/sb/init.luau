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

local Log = require("shared/log")

--[[
	We bundle all modules into one script, which all get inlined above this one.

	But due https://github.com/seaofvoices/darklua/pull/147, all bundled modules are no longer ran on startup.
	Here we load all bundled modules before modying the env and destroying the script (so the modules can get whatever they need before we remove them).
	
	This is a kinda hacky solution, and might break in a future darklua release.
	But it keeps the old behavior darklua used to had. Which was useful for clearing the env and destroying the script.
]]

do
	Log.debug("Loading modules...")

	-- selene: allow(undefined_variable)
	local modules = __DARKLUA_BUNDLE_MODULES -- Check .darklua.json
	for name, _ in modules do
		if name ~= "cache" and name ~= "load" then -- darklua places all modules, the load function, and cache table in the same table (we don't want to call cache and load).
			modules.load(name)
		end
	end
end

setfenv(1, {})

local networkAttribute = { next(script:GetAttributes()) }

-- Fetch assets and destroy script
Log.debug("Fetching assets...")

local sbActor = script.Parent

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
Log.debug("Initializing modules...")

local Network = require("client/network")
local Chat = require("client/chat")
local StarterScripts = require("client/starterScripts")

Network:Init(networkAttribute)
Chat:Init()
StarterScripts:Init()

-- Finalize
Log.debug("Finalizing...")
Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms`)

return nil
