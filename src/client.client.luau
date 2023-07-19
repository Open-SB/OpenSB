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

-- These are replaced later
local _print = print
local _warn = warn

setfenv(1, {})

local debugEnabled = game:GetService("RunService"):IsStudio()
local function debug(...: any)
	if debugEnabled then
		game:GetService("TestService"):Message("[SB Client] " .. table.concat({ ... }, " "))
	end
end

local function print(...: any)
	_print("[SB Client]", ...)
end

local function warn(...: any)
	_warn("[SB Client]", ...)
end

-- Fetch assets and destroy script

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			script:Destroy()
			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

-- Services and modules
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Network = {}

-- Network
do
	Network.attributeName, Network.attributeValue = next(script:GetAttributes())

	local registeredEvents: { [string]: (...unknown) -> nil } = {}
	function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
		if registeredEvents[name] then
			warn(`Network event "{name}" was overwritten`)
		end

		registeredEvents[name] = callback
	end
end

debug(`Loaded in {math.round((os.clock() - __start) * 1000)}ms`)
