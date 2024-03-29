--!nonstrict
--	// FileName: ChatScript.lua
--	// Written by: Xsitsu
--	// Description: Hooks main chat module up to Topbar in corescripts.

local FFlagUserHandleChatHotKeyWithContextActionService = false
do
	local ok, value = pcall(function()
		return UserSettings():IsUserFeatureEnabled("UserHandleChatHotKeyWithContextActionService")
	end)
	if ok then
		FFlagUserHandleChatHotKeyWithContextActionService = value
	end
end

local chatFolder = script.Parent

local StarterGui = game:GetService("StarterGui")
local GuiService = game:GetService("GuiService")
-- local ChatService = game:GetService("Chat")
-- local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- local MAX_COREGUI_CONNECTION_ATTEMPTS = 10

local ClientChatModules = chatFolder:WaitForChild("ClientChatModules")
local ChatSettings = require(ClientChatModules:WaitForChild("ChatSettings"))

-- Connect loop up here instead of at the end of the script, because calling DoEverything() and loading chat yields the script for some time.
-- (We want to be one of the first things to connect to PostSimulation, so our function gets called last.)
local args = { function() end }
game:GetService("RunService").PostSimulation:Connect(function()
	pcall(unpack(args))
end)

local containerTable = {}
local function DoEverything()
	local Chat = require(script:WaitForChild("ChatMain"))

	containerTable.ChatWindow = {}
	containerTable.SetCore = {}
	containerTable.GetCore = {}

	containerTable.ChatWindow.ChatTypes = {}
	containerTable.ChatWindow.ChatTypes.BubbleChatEnabled = ChatSettings.BubbleChatEnabled
	containerTable.ChatWindow.ChatTypes.ClassicChatEnabled = ChatSettings.ClassicChatEnabled

	--// Connection functions
	local function ConnectEvent(name, checkLastState)
		local event = Instance.new("BindableEvent")
		event.Name = name
		containerTable.ChatWindow[name] = event

		if checkLastState then
			local lastState
			event.Event:connect(function(state)
				if state ~= lastState then
					lastState = state
					Chat[name](Chat, state)
				end
			end)

			return
		end

		event.Event:connect(function(...)
			Chat[name](Chat, ...)
		end)
	end

	local function ConnectFunction(name)
		local func = Instance.new("BindableFunction")
		func.Name = name
		containerTable.ChatWindow[name] = func

		func.OnInvoke = function(...)
			return Chat[name](Chat, ...)
		end
	end

	local function ReverseConnectEvent(name)
		local event = Instance.new("BindableEvent")
		event.Name = name
		containerTable.ChatWindow[name] = event

		Chat[name]:connect(function(...)
			event:Fire(...)
		end)
	end

	local function ConnectSignal(name, checkLastState)
		local event = Instance.new("BindableEvent")
		event.Name = name
		containerTable.ChatWindow[name] = event

		if checkLastState then
			local lastState
			event.Event:connect(function(state)
				if state ~= lastState then
					lastState = state
					Chat[name]:fire(state)
				end
			end)

			return
		end

		event.Event:connect(function(...)
			Chat[name]:fire(...)
		end)
	end

	local function ConnectSetCore(name)
		local event = Instance.new("BindableEvent")
		event.Name = name
		containerTable.SetCore[name] = event

		event.Event:connect(function(...)
			Chat[name .. "Event"]:fire(...)
		end)
	end

	local function ConnectGetCore(name)
		local func = Instance.new("BindableFunction")
		func.Name = name
		containerTable.GetCore[name] = func

		func.OnInvoke = function(...)
			return Chat["f" .. name](...)
		end
	end

	--// Do connections
	ConnectEvent("ToggleVisibility")
	ConnectEvent("SetVisible", true)
	ConnectEvent("FocusChatBar")
	ConnectEvent("EnterWhisperState")
	ConnectFunction("GetVisibility")
	ConnectFunction("GetMessageCount")
	ConnectEvent("TopbarEnabledChanged", true)
	ConnectFunction("IsFocused")

	ReverseConnectEvent("ChatBarFocusChanged")
	ReverseConnectEvent("VisibilityStateChanged")
	ReverseConnectEvent("MessagesChanged")
	ReverseConnectEvent("MessagePosted")

	ConnectSignal("CoreGuiEnabled", true)

	ConnectSetCore("ChatMakeSystemMessage")
	ConnectSetCore("ChatWindowPosition")
	ConnectSetCore("ChatWindowSize")
	ConnectGetCore("ChatWindowPosition")
	ConnectGetCore("ChatWindowSize")
	ConnectSetCore("ChatBarDisabled")
	ConnectGetCore("ChatBarDisabled")

	if not FFlagUserHandleChatHotKeyWithContextActionService then
		ConnectEvent("SpecialKeyPressed")
	end

	--SetCoreGuiChatConnections(containerTable)
end

-- function SetCoreGuiChatConnections(containerTable)
-- 	local tries = 0
-- 	while tries < MAX_COREGUI_CONNECTION_ATTEMPTS do
-- 		tries = tries + 1
-- 		local success, ret = pcall(function()
-- 			StarterGui:SetCore("CoreGuiChatConnections", containerTable)
-- 		end)
-- 		if success then
-- 			break
-- 		end
-- 		if not success and tries == MAX_COREGUI_CONNECTION_ATTEMPTS then
-- 			error("Error calling SetCore CoreGuiChatConnections: " .. ret)
-- 		end
-- 		wait()
-- 	end
-- end

-- function checkBothChatTypesDisabled()
-- 	if ChatSettings.BubbleChatEnabled ~= nil then
-- 		if ChatSettings.ClassicChatEnabled ~= nil then
-- 			return not (ChatSettings.BubbleChatEnabled or ChatSettings.ClassicChatEnabled)
-- 		end
-- 	end
-- 	return false
-- end

if not GuiService:IsTenFootInterface() then
	-- if not checkBothChatTypesDisabled() then
	DoEverything()
	-- else
	-- 	containerTable.ChatWindow = {}

	-- 	containerTable.ChatWindow.ChatTypes = {}
	-- 	containerTable.ChatWindow.ChatTypes.BubbleChatEnabled = false
	-- 	containerTable.ChatWindow.ChatTypes.ClassicChatEnabled = false
	-- 	SetCoreGuiChatConnections(containerTable)
	-- end
else
	-- Make init data request to register as a speaker
	-- local EventFolder = ReplicatedStorage:WaitForChild("DefaultChatSystemChatEvents")
	-- EventFolder.GetInitDataRequest:InvokeServer()

	do
		local objectValue = chatFolder:WaitForChild("networkProxy")
		objectValue.Value = nil
		objectValue:Destroy()
	end

	local networkInvokeProxy
	do
		local objectValue = chatFolder:WaitForChild("networkInvokeProxy")
		networkInvokeProxy = objectValue.Value
		objectValue.Value = nil
		objectValue:Destroy()
	end

	networkInvokeProxy:InvokeServer("GetInitDataRequest")
end

pcall(StarterGui.SetCore, StarterGui, "CoreGuiChatConnections", containerTable)

args = table.create(80, task.defer)
table.insert(args, function()
	pcall(StarterGui.SetCore, StarterGui, "CoreGuiChatConnections", containerTable)
end)

return nil
