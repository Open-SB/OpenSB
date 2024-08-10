local World = require("server/world")

local Players = game:GetService("Players")

local function setCharacterRigType(player: Player, rigType: Enum.HumanoidRigType)
	local character = player.Character
	if not character then
		return "You don't have a character."
	end

	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return "You don't have a humanoid."
	end

	local rig = Players:CreateHumanoidModelFromDescription(humanoid:GetAppliedDescription(), rigType)
	rig.Name = player.Name

	local healthScript = character:FindFirstChild("Health")
	if healthScript and healthScript:IsA("Script") then
		Instance.fromExisting(healthScript).Parent = rig
	end

	player.Character = rig
	rig.Parent = workspace
	rig:PivotTo(character:GetPivot())
	character:Destroy()

	return `Got {rigType.Name} character.`
end

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

	--:base
	define("base", function()
		World:AddBase()

		return "Got base."
	end)

	--:noBase
	defineValidator("noBase", function()
		return World.Base ~= nil, "No base currently exists."
	end)

	define("noBase", function()
		World:RemoveBase()

		return "Got no base."
	end)

	--:respawn
	define("respawn", function(context)
		context.Player:LoadCharacter()

		return "Got respawn."
	end)

	--:refresh
	define("refresh", function(context)
		local player = context.Player

		-- Check if the client sent a character location.
		if type(context.Data.Location) == "CFrame" then
			player.CharacterAdded:Once(function(newCharacter)
				while not newCharacter.Parent do
					newCharacter.AncestryChanged:Wait()
				end

				task.wait()

				-- Get the latest location from the old character and teleport the new on there.
				newCharacter:PivotTo(context.Data.Location)
			end)
		end

		player:LoadCharacter()

		return "Got refresh."
	end)

	--:nil
	defineValidator("nil", function(context)
		return context.Player.Character ~= nil, "You already don't have a character."
	end)

	define("nil", function(context)
		context.Player.Character = nil

		return "Got nil."
	end)

	--:clear
	define("clear", function()
		World:Clear()

		return "Got clear."
	end)

	--:rig6
	define("rig6", function(context)
		return setCharacterRigType(context.Player, Enum.HumanoidRigType.R6)
	end)

	--:rig15
	define("rig15", function(context)
		return setCharacterRigType(context.Player, Enum.HumanoidRigType.R15)
	end)
end
