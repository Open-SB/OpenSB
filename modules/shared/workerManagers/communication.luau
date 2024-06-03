local setmetatable = setmetatable
local table = table
local error = error

local Signal = require("shared/signal")
local Functions = require("shared/functions")

local MangerCommunication = {}
MangerCommunication.__index = MangerCommunication

function MangerCommunication.new(...)
	local self = setmetatable({}, MangerCommunication)
	self:init(...)

	return self
end

function MangerCommunication:init(
	send: BindableEvent,
	recieve: BindableEvent,
	invoke: BindableFunction,
	invoked: BindableFunction
)
	self.__send = send
	self.__invoke = invoke

	self.__events = {}
	self.__invokes = {}

	recieve.Event:Connect(function(topic: string, ...)
		local event = self.__events[topic]
		if not event then
			return
		end

		event:Fire(...)
	end)

	invoked.OnInvoke = function(topic: string, ...)
		local callback = self.__invokes[topic]
		if not callback then
			return error(`"{topic}" is not a valid topic.`, 2)
		end

		return callback(...)
	end

	table.freeze(self)
end

function MangerCommunication:on(topic: string, callback: () -> never)
	-- This will not destroy the signal once all connections are disconnected, but it's likely this will never happen.
	-- If we add topics that are temporary and used once then this should be reworked to avoid memory leaks.

	local event = self.__events[topic]
	if not event then
		event = Signal.new()
		self.__events[topic] = event
	end

	return event:Connect(callback)
end

function MangerCommunication:onInvoke(topic: string, callback: () -> never)
	self.__invokes[topic] = callback
end

function MangerCommunication:Send(topic: string, ...)
	self.__send:Fire(topic, ...)
end

function MangerCommunication:Invoke(topic: string, ...)
	return self.__invoke:Invoke(topic, ...)
end

return MangerCommunication
