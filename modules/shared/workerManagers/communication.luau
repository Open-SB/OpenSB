local setmetatable = setmetatable
local table = table
local error = error
local warn = warn
local print = print

local Enum = require("shared/enum")
local Signal = require("shared/signal")
local Functions = require("shared/functions")

local Method = Enum({
	"Fire",
	"Invoke",
	"InvokeResult",
})

local MangerCommunication = {}
MangerCommunication.__index = MangerCommunication

function MangerCommunication.new(...)
	local self = setmetatable({}, MangerCommunication)
	self:init(...)

	return self
end

function MangerCommunication:init(send: BindableEvent, recieve: BindableEvent)
	self.__send = send

	self.__events = {}

	self.__invokeCallbacks = {}
	self.__invokeResults = {}

	recieve.Event:Connect(function(method, topic: string, ...)
		if method == Method.Fire then
			local event = self.__events[topic]
			if not event then
				return
			end

			event:Fire(...)
		elseif method == Method.Invoke then
			local callback = self.__invokeCallbacks[topic]
			if not callback then
				return error(`"{topic}" is not a valid topic.`, 2)
			end

			(function(id: string, ...)
				send:Fire(Method.InvokeResult, topic, id, callback(...))
			end)(...)
		elseif method == Method.InvokeResult then
			(function(id: string, ...)
				local invokeResult = self.__invokeResults[id]
				if not invokeResult then
					return
				end

				invokeResult:Fire(...)
			end)(...)
		end
	end)

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
	self.__invokeCallbacks[topic] = callback
end

function MangerCommunication:Send(topic: string, ...)
	self.__send:Fire(Method.Fire, topic, ...)
end

function MangerCommunication:Invoke(topic: string, ...)
	local id
	repeat
		id = Functions.randomString(8)
	until self.__invokeResults[id] == nil

	local signal = Signal.new()
	self.__invokeResults[id] = signal

	-- Defer so we can actually setup a :Wait() listener before the invoked function returns
	task.defer(self.__send.Fire, self.__send, Method.Invoke, topic, id, ...)

	return (function(...)
		self.__invokeResults[id] = nil
		signal:Destroy()

		return ...
	end)(signal:Wait())
end

return MangerCommunication
