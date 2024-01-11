local Instance = Instance
local _require = require
local task = task

-- This module loads a forked version of Roblox's legacy chat that is more secure and better suited for a script builder.
local chatFolder = script:WaitForChild("chatFolder"):Clone()

-- Only giving the chatscript a proxy is safer than giving it the entire network module
local networkProxy = Instance.new("BindableEvent")
networkProxy:Destroy()

-- We create an object value so the chat script doesn't need to destroy the bindable (if it were it would disconnect the connection this script makes)
do
	local objectValue = Instance.new("ObjectValue")
	objectValue.Name = "networkProxy"
	objectValue.Value = networkProxy
	objectValue.Parent = chatFolder
end

-- Create a bindable function for :InvokeServer()
local networkInvokeProxy = Instance.new("BindableFunction")
networkInvokeProxy:Destroy()

do
	local objectValue = Instance.new("ObjectValue")
	objectValue.Name = "networkInvokeProxy"
	objectValue.Value = networkInvokeProxy
	objectValue.Parent = chatFolder
end

local Network = require("client/network")
local Log = require("shared/log")
local Signal = require("shared/signal")

local Chat = {
	hooks = {},
}

function Chat:ConnectHook(remoteName, callback)
	local hook = self.hooks[remoteName]
	if not hook then
		hook = Signal.new()
		self.hooks[remoteName] = hook
	end

	return hook:Connect(callback)
end

function Chat:Init()
	networkProxy.Event:Connect(function(requestType, remoteName, ...)
		if requestType == 0 then -- Connect event
			local callback = ...
			Network:RegisterEvent("chat://" .. remoteName, callback)
		elseif requestType == 1 then -- Fire server
			Network:FireServer("chat://" .. remoteName, ...)

			local hook = self.hooks[remoteName]
			if hook then
				hook:Fire(...)
			end
		end
	end)

	networkInvokeProxy.OnInvoke = function(remoteName, ...)
		return Network:InvokeServer("chat://" .. remoteName, ...)
	end

	Log.debug("Loading chat...")
	task.defer(_require, chatFolder:WaitForChild("ChatScript"))
end

return Chat
