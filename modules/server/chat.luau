-- This module loads a forked version of Roblox's legacy chat that is more secure and better suited for a script builder.

local Network = require("server/network")
local Log = require("shared/log")
local Assets = require("shared/assets")

local Chat = {}

local chatFolder = Assets:get("chat")

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

function Chat:Init()
	networkProxy.Event:Connect(function(requestType, remoteName, ...)
		if requestType == 0 then -- Connect event
			local callback = ...
			Network:RegisterEvent("chat://" .. remoteName, callback)
		elseif requestType == 1 then -- Connect function
			local callback = ...
			Network:RegisterFunction("chat://" .. remoteName, callback)
		elseif requestType == 2 then -- Fire client
			local player = ...
			Network:FireClient(player, "chat://" .. remoteName, select(2, ...))
		elseif requestType == 3 then -- Fire all clients
			Network:FireAllClients("chat://" .. remoteName, ...)
		end
	end)

	Log.debug("Loading chat...")
	task.defer(require, chatFolder:WaitForChild("ChatServiceRunner"))
end

return Chat
