local setmetatable = setmetatable
local table = table
local error = error

local Signal = require("@shared/signal")
local Log = require("@shared/log")

local ManagerCommunication = {}
ManagerCommunication.__index = ManagerCommunication

function ManagerCommunication.new(...)
	local self = setmetatable({}, ManagerCommunication)
	self:init(...)

	return self
end

function ManagerCommunication:init(
	send: BindableEvent,
	receive: BindableEvent,
	invoke: BindableFunction,
	invoked: BindableFunction
)
	self.__send = send
	self.__invoke = invoke

	self.__events = {}
	self.__invokes = {}

	self.__sendOnReady = {}
	self.__resumeOnReady = {}

	receive.Event:Connect(function(topic: string, ...)
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

	self:once("ready", function()
		local toSend = table.clone(self.__sendOnReady)
		table.clear(self.__sendOnReady)
		table.freeze(self.__sendOnReady) -- Marks that we're ready

		local toResume = table.clone(self.__resumeOnReady)
		table.clear(self.__resumeOnReady)
		table.freeze(self.__resumeOnReady)

		Log.debug(`Receiver ready! Sending {#toSend} events and resuming {#toResume} threads.`)

		for _, data in ipairs(toSend) do
			self.__send:Fire(unpack(data, 1, data.n))
		end

		for _, thread in ipairs(toResume) do
			pcall(coroutine.resume, thread)
		end
	end)

	table.freeze(self)
end

function ManagerCommunication:isReceiverReady()
	return table.isfrozen(self.__sendOnReady)
end

function ManagerCommunication:awaitReceiverReady()
	if self:isReceiverReady() then
		return
	end

	table.insert(self.__resumeOnReady, coroutine.running())
	coroutine.yield()
end

function ManagerCommunication:ready(awaitReceiver: boolean)
	Log.debug("Communication ready!")

	if awaitReceiver then
		self:Send("ready")
		return
	end

	self.__send:Fire("ready")
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
	elseif _G.dev then
		Log.warn(
			debug.traceback(
				"You are calling once on an event that already exists; this will destroy the event and delete the topic after the event is fired. This can and most likely WILL lead to unexpected behavior."
			)
		)
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
	if self:isReceiverReady() then
		self.__send:Fire(topic, ...)
	else
		table.insert(self.__sendOnReady, table.pack(topic, ...))
	end
end

function ManagerCommunication:Invoke(topic: string, ...)
	self:awaitReceiverReady()
	return self.__invoke:Invoke(topic, ...)
end

return ManagerCommunication
