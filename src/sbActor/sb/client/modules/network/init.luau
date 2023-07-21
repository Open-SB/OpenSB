--!strict
local setfenv = setfenv
local script = script
local require = require
local game = game
local error = error
local unpack = unpack
local task = task
local table = table

setfenv(1, {})

local services = table.clone(require(script:WaitForChild("services")))

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Modules = require(script.Parent)
script = nil

local Log = Modules.require("log")
local Functions = Modules.require("functions")

local attributeName, attributeValue
local remotes = {}

local Network = {}

function Network.setAttribute(attribute: {})
	Network.setAttribute = Functions.empty -- Prevent future changes
	attributeName, attributeValue = unpack(attribute)
end

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local function connectRemote(remote) end

task.defer(function()
	while not attributeName or not attributeValue do
		task.wait()
	end
end)

return { Network }
