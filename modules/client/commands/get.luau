local Enum = Enum
local game = game
local warn = warn
local task = task
local workspace = workspace

return function(Commands)
	-- Load shared definitions
	require("shared/commands/get")(Commands)

	local namespace = "get"
	local function defineValidator(...)
		Commands:DefineValidator(namespace, ...)
	end
	local function define(...)
		Commands:Define(namespace, ...)
	end

	--:refresh
	define("refresh", function(context)
		local player = context.Player
		local character = player.Character
		if not character then
			return
		end

		-- Give server character location to teleport on server aswell (to avoid issues with player showing up on spawn for others).
		context.Data.Location = character:GetPivot()

		player.CharacterAdded:Once(function(newCharacter)
			while not newCharacter.Parent do
				newCharacter.AncestryChanged:Wait()
			end

			task.wait()

			-- Get the latest location from the old character and teleport the new on there.
			newCharacter:PivotTo(character:GetPivot())
		end)
	end)

	--:fixCamera
	define("fixCamera", function(context)
		local currentCFrame = workspace.CurrentCamera.CFrame
		workspace:GetPropertyChangedSignal("CurrentCamera"):Once(function()
			local camera = workspace.CurrentCamera
			camera.CameraSubject = context.Player.Character -- Roblox sets it to humanoid for you.
			camera.CameraType = Enum.CameraType.Custom
			camera.CFrame = currentCFrame
		end)

		workspace.CurrentCamera:Destroy()

		local player = context.Player
		player.CameraMaxZoomDistance = 400
		player.CameraMinZoomDistance = 0.5
		player.CameraMode = Enum.CameraMode.Classic
		player.HealthDisplayDistance = 100
		player.NameDisplayDistance = 100
	end)
end
