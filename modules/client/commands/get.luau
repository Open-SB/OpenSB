local Output = require("client/output")
local ScriptManager = require("client/scriptManager")
local UI = require("client/ui")

return function(Commands)
	-- Load shared definitions
	require("shared/commands/get")(Commands)

	local _namespace = "get"
	local function defineValidator(...)
		Commands:DefineValidator(_namespace, ...)
	end
	local function define(...)
		Commands:Define(_namespace, ...)
	end

	--:commands
	define("commands", function()
		for _, data in ipairs({
			{ "default", "Commands:" },
			{ "get", "Get commands:" },
		}) do
			local namespace = Commands.namespaces[data[1]]
			Output:append(Output.MessageType.System, data[2])

			if namespace.prefixes then
				Output:append(Output.MessageType.Information, `Prefixes: {table.concat(namespace.prefixes, ", ")}`)
			end

			local sorted = {}
			for _, command in namespace.commands do
				table.insert(sorted, command)
			end

			table.sort(sorted, function(a, b)
				return a.aliases[1] < b.aliases[1]
			end)

			for _, command in ipairs(sorted) do
				Output:append(Output.MessageType.Log, `{table.concat(command.aliases, ", ")}: {command.description}`)
			end
		end
	end)

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

		return "Got camera fix."
	end)

	--:noGui
	define("noGui", function(context)
		local playerGui = context.Player:FindFirstChildOfClass("PlayerGui")
		if not playerGui then
			return
		end

		for _, gui in ipairs(playerGui:GetChildren()) do
			if UI:IsScriptBuilderUI(gui) then
				continue
			end

			gui:Destroy()
		end

		return "Got no gui."
	end)

	--:noScripts
	define("noScripts", function()
		task.defer(ScriptManager.StopScripts, ScriptManager)
	end)

	--:noLocalScripts
	define("noLocalScripts", function()
		task.defer(ScriptManager.StopLocalScripts, ScriptManager)
	end)
end
