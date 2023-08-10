--!strict
local Instance = Instance
local setfenv = setfenv
local script = script
local require = require
local task = task

setfenv(1, {})

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

local Modules = require(script.Parent)
script = nil

local Network = Modules.require("network")
local Log = Modules.require("log")

local Chat = {}

networkProxy.Event:Connect(function(requestType, remoteName, ...)
	if requestType == 0 then -- Connect event
		local callback = ...
		Network:RegisterEvent("chat://" .. remoteName, callback)
	elseif requestType == 1 then -- Fire server
		Network:FireServer("chat://" .. remoteName, ...)
	end
end)

networkInvokeProxy.OnInvoke = function(remoteName, ...)
	return Network:InvokeServer("chat://" .. remoteName, ...)
end

Log.debug("Loading chat...")
require(chatFolder:WaitForChild("ChatScript"))

return { Chat }
