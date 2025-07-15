local setmetatable = setmetatable
local table = table
local error = error

local Signal = require("shared/signal")
local Log = require("shared/log")

local ManagerCommunication = {}
ManagerCommunication.__index = ManagerCommunication

function ManagerCommunication.new(...)
	local self = setmetatable({}, ManagerCommunication)
	self:init(...)

	return self
end

function ManagerCommunication:init(
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

function ManagerCommunication:on(topic: string, callback: (any...) -> never)
	-- This will not destroy the signal once all connections are disconnected, but it's likely this will never happen.
	-- If we add topics that are temporary and used once then this should be reworked to avoid memory leaks.

	local event = self.__events[topic]
	if not event then
		event = Signal.new()
		self.__events[topic] = event
	end

	return event:Connect(callback)
end

function ManagerCommunication:once(topic: string, callback: (any...) -> never)
	local event = self.__events[topic]
	if not event then
		event = Signal.new()
		self.__events[topic] = event
	else
		if _G.dev then
			Log.warn(
				"You are calling once on an event that already exists; this will destroy the event and delete the topic after the event is fired. This can and most likely WILL lead to unexpected behavior."
			)
		end
	end

	return event:Once(function(...)
		event:Destroy()
		self.__events[topic] = nil
		callback(...)
	end)
end

function ManagerCommunication:onInvoke(topic: string, callback: (any...) -> any...)
	self.__invokes[topic] = callback
end

function ManagerCommunication:Send(topic: string, ...)
	self.__send:Fire(topic, ...)
end

function ManagerCommunication:Invoke(topic: string, ...)
	return self.__invoke:Invoke(topic, ...)
end

return ManagerCommunication
