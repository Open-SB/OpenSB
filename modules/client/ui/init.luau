local Players = game:GetService("Players")

local Output = require("client/output")
local Chat = require("client/chat")
local Log = require("shared/log")
local Maid = require("shared/maid")
local Signal = require("shared/signal")
local Functions = require("shared/functions")

local App = require("./app")
local create = require("./create")

local UI = {}
UI.PlayerGui = nil
UI.ScreenGui = nil
UI.IsLoaded = false
UI.Loaded = Signal.new()

local UIMaid = Maid.new()
function UI:Create()
	Log.debug("Creating UI...")
	UIMaid:DoCleaning()

	local screenGui = create("ScreenGui")({
		Name = Functions.randomInstanceName(),
		Archivable = false,
		ScreenInsets = Enum.ScreenInsets.CoreUISafeInsets,
		DisplayOrder = 2147483647,
		ResetOnSpawn = false,
		ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
	})

	UIMaid.screenGui = screenGui
	UIMaid.screenGuiChanged = screenGui.Changed:Connect(function(property)
		if property == "AbsoluteSize" or property == "AbsolutePosition" then
			return
		end

		if property == "Parent" and screenGui.Parent == UI.PlayerGui then
			return
		end

		UI:Create()
	end)

	UI.ScreenGui = screenGui

	App.mount(screenGui)
	screenGui.Parent = UI.PlayerGui
end

function UI:WaitUntilLoaded()
	if not UI.IsLoaded then
		UI.Loaded:Wait()
	end
end

function UI:MakeScriptPrompt(bindable: BindableEvent, owner: Player, script: BaseScript)
	App.scriptPrompt(bindable, owner, script)
end

function UI:IsScriptBuilderUI(screenGui: ScreenGui?)
	if not screenGui then
		return false
	end

	return screenGui == UI.ScreenGui or screenGui == Chat.ScreenGui
end

function UI:Init()
	Log.debug("Initializing UI...")

	-- Remove loading screen.
	game:GetService("ReplicatedFirst"):RemoveDefaultLoadingScreen()

	-- Wait for LocalPlayer and PlayerGui, then create UI.
	task.defer(function()
		local localPlayer = Players.LocalPlayer or Players:GetPropertyChangedSignal("LocalPlayer"):Wait()

		UI.PlayerGui = localPlayer:FindFirstChildOfClass("PlayerGui")
		while not UI.PlayerGui do
			localPlayer.ChildAdded:Wait()
			UI.PlayerGui = localPlayer:FindFirstChildOfClass("PlayerGui")
		end

		UI:Create()
		Output.MessageOut:Connect(App.onMessageOut)
		Output.MessageIdDropped:Connect(App.onMessageIdDropped)

		UI.IsLoaded = true
		UI.Loaded:Fire()
	end)
end

return UI
