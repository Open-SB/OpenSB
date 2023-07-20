--!strict
local setfenv = setfenv
local script = script
local require = require
local game = game
local error = error

setfenv(1, {})

local Modules = require(script.Parent)
script = nil

local Log = Modules.require("log")

local Network = {}
local attributeName, attributeValue

function Network.setAttribute(attribute: {})
	if attributeName and attributeValue then
		error("Attribute is already set.", 2)

		return
	end
	Log.print(attribute)
	attributeName, attributeValue = unpack(attribute)
end

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

return { Network }
