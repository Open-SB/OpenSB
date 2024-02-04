local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")

local Commands = require("client/commands")
local CommandInputContext = require("shared/commands/inputContexts")
local Maid = require("shared/maid")
local Signal = require("shared/signal")

local create = require("./create")

local APP_ASPECT_RATIO = 2 / 1
local APP_MAX_SIZE, APP_MIN_SIZE = 275, 200
local APP_PADDING = 16
local APP_CORNER_SIZE = 6
local APP_COLUMN_WIDTH, APP_ROW_HEIGHT = 0.25, 0.1
local APP_BACKGROUND_COLOR = Color3.new(0, 0, 0)
local APP_CONTENT_COLOR = Color3.new(1, 1, 1)
local APP_TEXT_FONT =
	Font.new("rbxasset://fonts/families/RobotoMono.json", Enum.FontWeight.Medium, Enum.FontStyle.Normal)
local APP_TEXT_PADDING = {
	PaddingBottom = UDim.new(0, 6),
	PaddingLeft = UDim.new(0, 8),
	PaddingRight = UDim.new(0, 8),
	PaddingTop = UDim.new(0, 6),
}

local APP_SCROLL_PADDING = 4
local APP_SCROLL_THICKNESS = 4
local APP_SCROLL_TRANSPARENCY = 0

local OUTPUT_TRANSPARENCY = 0.6
local OUTPUT_TEXT_FONT = APP_TEXT_FONT
local OUTPUT_TEXT_SIZE = 14 -- If the UI is att max size

local COMMAND_BAR_TRANSPARENCY = 0
local COMMAND_BAR_INPUT_KEY = Enum.KeyCode.Quote

local App = {}
App.OutputOpen = true

local AppMaid = Maid.new()

local root

local commandBarBackground
local commandBarInput
local outputToggleLabel
local commandBar

local output
local outputScale
local outputList

local enterPressedKeycodes = {
	[Enum.KeyCode.Return] = true,
	[Enum.KeyCode.KeypadEnter] = true,
}

-- Checks if the enter key is about to be pressed, useful for checking if a textBox enterPressed was spoofed with :ReleaseFocus(true)
local function checkIfEnterPressed()
	local event = Signal.new()

	local thread = task.delay(0, event.Fire, event, false)
	local connection = UserInputService.InputBegan:Connect(function(input)
		if input.UserInputType == Enum.UserInputType.Keyboard and enterPressedKeycodes[input.KeyCode] then
			event:Fire(true)
		end
	end)

	local result = event:Wait()
	task.cancel(thread)
	connection:Disconnect()
	event:Destroy()

	return result
end

local function updateOutputScale()
	local scale = root.AbsoluteSize.Y / APP_MAX_SIZE
	outputScale.Scale = scale
	outputList.Size = UDim2.fromScale(1 / scale, 1 / scale)
end

local function setOutputOpen(open)
	App.OutputOpen = open

	commandBarBackground.Size = UDim2.new(1, 0, 1, if open then APP_CORNER_SIZE else 0)
	outputToggleLabel.Text = if open then "Close output" else "Open output"
	output.Visible = open
end

local outputLabels = {}
local function clearOutput()
	for _, label in ipairs(outputLabels) do
		label:Destroy()
	end
	table.clear(outputLabels)

	outputList.CanvasSize = UDim2.new()
	outputList.CanvasPosition = Vector2.zero
end

function App.onMessageOut(dateTime, message, color)
	local formattedDateTime = dateTime:FormatLocalTime("LTS", Players.LocalPlayer.LocaleId)

	-- Determine if we are scrolled all down (with a one pixel safe zone),
	-- if we are then we should automatically scroll to the bottom after adding a new label.
	local wasAtBottom = outputList.AbsoluteCanvasSize.Y - outputList.AbsoluteWindowSize.Y - 1
		<= outputList.CanvasPosition.Y

	local label = create "TextLabel" {
		Parent = outputList,
		AutomaticSize = Enum.AutomaticSize.XY,
		BackgroundTransparency = 1,
		FontFace = OUTPUT_TEXT_FONT,
		Text = `{formattedDateTime}  {message}`,
		TextColor3 = color,
		TextSize = OUTPUT_TEXT_SIZE,
		TextWrapped = true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Center,
	}

	table.insert(outputLabels, label)

	if wasAtBottom then
		outputList.CanvasPosition =
			Vector2.new(outputList.CanvasPosition.X, outputList.AbsoluteCanvasSize.Y - outputList.AbsoluteWindowSize.Y)
	end
end

function App.mount(screenGui)
	AppMaid:DoCleaning()

	commandBarBackground = create "Frame" {
		AnchorPoint = Vector2.new(0, 1),
		BackgroundColor3 = APP_BACKGROUND_COLOR,
		BackgroundTransparency = COMMAND_BAR_TRANSPARENCY,
		BorderSizePixel = 0,
		Position = UDim2.fromScale(0, 1),
		ZIndex = 0,

		create "UICorner" {
			CornerRadius = UDim.new(0, APP_CORNER_SIZE),
		},
	}

	commandBarInput = create "TextBox" {
		BackgroundTransparency = 1,
		ClearTextOnFocus = false,
		Size = UDim2.fromScale(1, 1),
		FontFace = APP_TEXT_FONT,
		PlaceholderColor3 = APP_CONTENT_COLOR:Lerp(APP_BACKGROUND_COLOR, 0.5),
		TextColor3 = APP_CONTENT_COLOR,
		PlaceholderText = `Click here or press {UserInputService:GetStringForKeyCode(COMMAND_BAR_INPUT_KEY)} to run a command`,
		Text = "",
		TextScaled = true,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Center,

		ReturnPressedFromOnScreenKeyboard = function()
			local input = commandBarInput.Text
			commandBarInput.Text = ""
			Commands:Process(input, CommandInputContext.CommandBar)
		end,
		FocusLost = function(enterPressed)
			if not enterPressed then
				return
			end

			local input = commandBarInput.Text
			if not checkIfEnterPressed() then
				return
			end

			commandBarInput.Text = ""
			Commands:Process(input, CommandInputContext.CommandBar)
		end,
	}

	AppMaid:GiveTask(UserInputService.InputBegan:Connect(function(input)
		if input.UserInputType ~= Enum.UserInputType.Keyboard then
			return
		end

		if input.KeyCode == COMMAND_BAR_INPUT_KEY then
			task.wait() -- Yield to avoid typing into the commandbar while capturing focus.

			commandBarInput:CaptureFocus()
		end
	end))

	outputToggleLabel = create "TextLabel" {
		BackgroundTransparency = 1,
		Size = UDim2.fromScale(1, 1),
		FontFace = APP_TEXT_FONT,
		TextColor3 = APP_CONTENT_COLOR,
		TextScaled = true,
	}

	commandBar = create "Frame" {
		AnchorPoint = Vector2.new(0, 1),
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		Position = UDim2.fromScale(0, 1),
		Size = UDim2.fromScale(1, APP_ROW_HEIGHT),
		ZIndex = 2,
		ClipsDescendants = true,

		commandBarBackground,

		create "TextButton" {
			BackgroundTransparency = 1,
			Size = UDim2.fromScale(APP_COLUMN_WIDTH, 1),
			Text = "",

			MouseButton1Click = function()
				setOutputOpen(not App.OutputOpen)
			end,

			create "UIPadding" { APP_TEXT_PADDING },

			outputToggleLabel,
		},

		create "Frame" {
			BackgroundColor3 = Color3.new(1, 1, 1),
			BackgroundTransparency = 0.5 * (1 + COMMAND_BAR_TRANSPARENCY),
			BorderSizePixel = 0,
			Position = UDim2.fromScale(APP_COLUMN_WIDTH, 0),
			Size = UDim2.new(0, 1, 1, 0),
			ZIndex = 2,
		},

		create "Frame" {
			AnchorPoint = Vector2.new(1, 0),
			BackgroundTransparency = 1,
			Position = UDim2.fromScale(1, 0),
			Size = UDim2.fromScale(1 - APP_COLUMN_WIDTH, 1),

			create "UIPadding" { APP_TEXT_PADDING },

			commandBarInput,
		},
	}

	outputScale = create "UIScale" {}
	outputList = create "ScrollingFrame" {
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		AutomaticCanvasSize = Enum.AutomaticSize.XY,
		ScrollBarImageColor3 = APP_CONTENT_COLOR,
		ScrollBarImageTransparency = APP_SCROLL_TRANSPARENCY,
		ScrollBarThickness = APP_SCROLL_THICKNESS,

		outputScale,

		create "UIPadding" {
			PaddingBottom = APP_TEXT_PADDING.PaddingBottom - UDim.new(0, APP_SCROLL_PADDING),
			PaddingLeft = APP_TEXT_PADDING.PaddingLeft - UDim.new(0, APP_SCROLL_PADDING),
			PaddingRight = APP_TEXT_PADDING.PaddingRight - UDim.new(0, APP_SCROLL_PADDING),
			PaddingTop = APP_TEXT_PADDING.PaddingTop - UDim.new(0, APP_SCROLL_PADDING),
		},

		create "UIListLayout" {},
	}

	output = create "Frame" {
		BackgroundTransparency = 1,
		Size = UDim2.fromScale(1, 1 - APP_ROW_HEIGHT),
		ClipsDescendants = true,

		create "Frame" {
			BackgroundColor3 = APP_BACKGROUND_COLOR,
			BackgroundTransparency = OUTPUT_TRANSPARENCY,
			BorderSizePixel = 0,
			Size = UDim2.fromScale(1, 1 / (1 - APP_ROW_HEIGHT)),

			create "UICorner" {
				CornerRadius = UDim.new(0, APP_CORNER_SIZE),
			},

			create "Frame" {
				BackgroundTransparency = 1,
				Size = UDim2.fromScale(APP_COLUMN_WIDTH, APP_ROW_HEIGHT),

				create "UIPadding" { APP_TEXT_PADDING },

				create "TextLabel" {
					BackgroundTransparency = 1,
					Size = UDim2.fromScale(1, 1),
					FontFace = APP_TEXT_FONT,
					TextColor3 = APP_CONTENT_COLOR,
					Text = "Scripts",
					TextScaled = true,
				},
			},

			create "Frame" {
				BackgroundColor3 = Color3.new(1, 1, 1),
				BackgroundTransparency = 0.5 * (1 + OUTPUT_TRANSPARENCY),
				BorderSizePixel = 0,
				Position = UDim2.fromScale(0, APP_ROW_HEIGHT),
				Size = UDim2.new(1, 0, 0, 1),
				ZIndex = 2,
			},

			create "Frame" {
				AnchorPoint = Vector2.new(1, 0),
				BackgroundTransparency = 1,
				Position = UDim2.fromScale(1, 0),
				Size = UDim2.fromScale(1 - APP_COLUMN_WIDTH, APP_ROW_HEIGHT),

				create "UIPadding" { APP_TEXT_PADDING },

				create "TextLabel" {
					BackgroundTransparency = 1,
					Size = UDim2.fromScale(1, 1),
					FontFace = APP_TEXT_FONT,
					TextColor3 = APP_CONTENT_COLOR,
					Text = "Output",
					TextScaled = true,
				},
			},

			create "TextButton" {
				AnchorPoint = Vector2.new(1, 0),
				AutomaticSize = Enum.AutomaticSize.X,
				BackgroundTransparency = 1,
				Position = UDim2.fromScale(1, 0),
				Size = UDim2.fromScale(0, APP_ROW_HEIGHT),
				Text = "",

				MouseButton1Click = clearOutput,

				create "UIPadding" { APP_TEXT_PADDING },

				create "TextLabel" {
					AutomaticSize = Enum.AutomaticSize.X,
					BackgroundTransparency = 1,
					Size = UDim2.fromScale(0, 1),
					FontFace = APP_TEXT_FONT,
					Text = "Clear",
					TextColor3 = APP_CONTENT_COLOR,
					TextScaled = true,
				},
			},

			create "Frame" {
				BackgroundColor3 = Color3.new(1, 1, 1),
				BackgroundTransparency = 0.5 * (1 + OUTPUT_TRANSPARENCY),
				BorderSizePixel = 0,
				Position = UDim2.fromScale(APP_COLUMN_WIDTH, 0),
				Size = UDim2.new(0, 1, 1, 0),
				ZIndex = 2,
			},

			create "Frame" {
				BackgroundTransparency = 1,
				Position = UDim2.fromScale(0, APP_ROW_HEIGHT),
				Size = UDim2.fromScale(APP_COLUMN_WIDTH, 1 - APP_ROW_HEIGHT * 2),

				create "UIPadding" {
					PaddingBottom = UDim.new(0, APP_SCROLL_PADDING),
					PaddingLeft = UDim.new(0, APP_SCROLL_PADDING),
					PaddingRight = UDim.new(0, APP_SCROLL_PADDING),
					PaddingTop = UDim.new(0, APP_SCROLL_PADDING),
				},

				create "ScrollingFrame" {
					BackgroundTransparency = 1,
					BorderSizePixel = 0,
					Size = UDim2.fromScale(1, 1),
					AutomaticCanvasSize = Enum.AutomaticSize.XY,
					ScrollBarImageColor3 = APP_CONTENT_COLOR,
					ScrollBarImageTransparency = APP_SCROLL_TRANSPARENCY,
					ScrollBarThickness = APP_SCROLL_THICKNESS,

					create "UIPadding" {
						PaddingBottom = UDim.new(0, 0),
						PaddingLeft = UDim.new(0, 0),
						PaddingRight = UDim.new(0, APP_SCROLL_PADDING),
						PaddingTop = UDim.new(0, 0),
					},
				},
			},

			create "Frame" {
				AnchorPoint = Vector2.new(1, 0),
				BackgroundTransparency = 1,
				Position = UDim2.fromScale(1, APP_ROW_HEIGHT),
				Size = UDim2.fromScale(1 - APP_COLUMN_WIDTH, 1 - APP_ROW_HEIGHT * 2),

				create "UIPadding" {
					PaddingBottom = UDim.new(0, APP_SCROLL_PADDING),
					PaddingLeft = UDim.new(0, APP_SCROLL_PADDING),
					PaddingRight = UDim.new(0, APP_SCROLL_PADDING),
					PaddingTop = UDim.new(0, APP_SCROLL_PADDING),
				},

				outputList,
			},
		},
	}

	create "UIPadding" {
		Parent = screenGui,
		PaddingBottom = UDim.new(0, APP_PADDING),
		PaddingLeft = UDim.new(0, APP_PADDING),
		PaddingRight = UDim.new(0, APP_PADDING),
		PaddingTop = UDim.new(0, APP_PADDING),
	}

	root = create "Frame" {
		Parent = screenGui,
		AnchorPoint = Vector2.new(0, 1),
		BackgroundTransparency = 1,
		Position = UDim2.fromScale(0, 1),
		Size = UDim2.fromScale(0.5, 1),

		create "UIAspectRatioConstraint" {
			AspectRatio = APP_ASPECT_RATIO,
		},

		create "UISizeConstraint" {
			MaxSize = Vector2.new(APP_MAX_SIZE * APP_ASPECT_RATIO, APP_MAX_SIZE),
			MinSize = Vector2.new(APP_MIN_SIZE * APP_ASPECT_RATIO, APP_MIN_SIZE),
		},

		commandBar,
		output,
	}

	updateOutputScale()
	AppMaid:GiveTask(root:GetPropertyChangedSignal("AbsoluteSize"):Connect(updateOutputScale))

	clearOutput()
	setOutputOpen(App.OutputOpen)
end

return App
