local World = require("@server/world")
local ScriptManager = require("@server/scriptManager")
local Output = require("@server/output")
local Functions = require("@shared/functions")
local Assets = require("@shared/assets")

local Players = game:GetService("Players")
local TeleportService = game:GetService("TeleportService")

local healthScript = Assets:get("Health")
local serverAnimateScripts = {
	[Enum.HumanoidRigType.R6] = Assets:get("R6Animate"),
	[Enum.HumanoidRigType.R15] = Assets:get("R15Animate"),
}

local function createRig(description: HumanoidDescription, rigType: Enum.HumanoidRigType)
	local rig = Players:CreateHumanoidModelFromDescription(description, rigType)
	healthScript:Clone().Parent = rig

	return rig
end

local function setCharacterRigType(player: Player, rigType: Enum.HumanoidRigType)
	local character = player.Character
	if not character then
		return "You don't have a character."
	end

	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not humanoid then
		return "You don't have a humanoid."
	end

	local rig = createRig(humanoid:GetAppliedDescription(), rigType)
	rig.Name = player.Name
	player.Character = rig

	rig.Parent = workspace
	rig:PivotTo(character:GetPivot())

	character:Destroy()

	return `Got {rigType.Name} character.`
end

local dummyHumanoidDescription = Instance.new("HumanoidDescription")
dummyHumanoidDescription.HeadColor = Color3.fromRGB(253, 234, 141)
dummyHumanoidDescription.LeftArmColor = Color3.fromRGB(253, 234, 141)
dummyHumanoidDescription.LeftLegColor = Color3.fromRGB(13, 105, 172)
dummyHumanoidDescription.RightArmColor = Color3.fromRGB(253, 234, 141)
dummyHumanoidDescription.RightLegColor = Color3.fromRGB(13, 105, 172)
dummyHumanoidDescription.TorsoColor = Color3.fromRGB(40, 127, 71)

local function createDummy(player: Player, rigType: Enum.HumanoidRigType)
	local dummy = createRig(dummyHumanoidDescription, rigType)
	dummy.Name = "Dummy"
	dummy:WaitForChild("Humanoid").DisplayName = `{Functions.formatPlayerName(player)}'s dummy`

	local animate = serverAnimateScripts[rigType]:Clone()
	animate.Name = "Animate"

	dummy:WaitForChild("Animate"):Destroy()
	animate.Parent = dummy

	dummy.Parent = workspace
	dummy.PrimaryPart:SetNetworkOwner(nil)

	local character = player.Character
	if character then
		dummy:PivotTo(character:GetPivot())
	end

	return `Got {rigType.Name} dummy.`
end

return function(Commands)
	-- Load shared definitions
	require("@shared/commands/get")(Commands)

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
		if typeof(context.Data.Location) == "CFrame" then
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

	--:rejoin
	defineValidator("rejoin", function()
		return Functions.getServerType() ~= "VIPServer", "You can't use rejoin command in VIP servers."
	end)

	define("rejoin", function(context)
		local teleportOptions = Instance.new("TeleportOptions")
		teleportOptions.ServerInstanceId = game.JobId

		Output:appendTo(context.Player, Output.MessageType.Success, "Rejoining...")
		TeleportService:TeleportAsync(game.PlaceId, { context.Player }, teleportOptions)
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

	--:fixLighting
	do
		local Terrain: Terrain = workspace:WaitForChild("Terrain")
		local Lighting = game:GetService("Lighting")

		define("fixLighting", function()
			Lighting:ClearAllChildren()

			while true do
				local Clouds = Terrain:FindFirstChildWhichIsA("Clouds")
				if not Clouds then
					break
				end

				Clouds:Destroy()
			end

			Lighting.Ambient = Color3.fromRGB(127, 127, 127)
			Lighting.Brightness = 1
			Lighting.ColorShift_Bottom = Color3.fromRGB(0, 0, 0)
			Lighting.ColorShift_Top = Color3.fromRGB(0, 0, 0)
			Lighting.EnvironmentDiffuseScale = 0
			Lighting.EnvironmentSpecularScale = 0
			Lighting.GlobalShadows = true
			Lighting.OutdoorAmbient = Color3.fromRGB(127, 127, 127)
			Lighting.ShadowSoftness = 0.5
			Lighting.ExposureCompensation = 0
			Lighting.FogColor = Color3.fromRGB(191, 191, 191)
			Lighting.FogEnd = 100000
			Lighting.FogStart = 0

			-- day time
			Lighting.ClockTime = 14.5

			return "Fixed lighting."
		end)
	end

	--:noGui
	define("noGui", function(context)
		local playerGui = context.Player:FindFirstChildOfClass("PlayerGui")
		if not playerGui then
			return
		end

		playerGui:ClearAllChildren()
	end)

	--:rig6
	define("rig6", function(context)
		return setCharacterRigType(context.Player, Enum.HumanoidRigType.R6)
	end)

	--:rig15
	define("rig15", function(context)
		return setCharacterRigType(context.Player, Enum.HumanoidRigType.R15)
	end)

	--:rig6dummy
	define("rig6dummy", function(context)
		return createDummy(context.Player, Enum.HumanoidRigType.R6)
	end)

	--:rig15dummy
	define("rig15dummy", function(context)
		return createDummy(context.Player, Enum.HumanoidRigType.R15)
	end)

	--:noScripts
	define("noScripts", function(context, arguments)
		if not arguments[1] or string.lower(arguments[1]) ~= "all" then
			ScriptManager:StopScripts(context.Player)
			return "Got no scripts."
		end

		ScriptManager:StopScripts()
		Output:appendToAll(Output.MessageType.Success, `{Functions.formatPlayerName(context.Player)} got no scripts.`)
	end)

	--:noServerScripts
	define("noServerScripts", function(context, arguments)
		if not arguments[1] or string.lower(arguments[1]) ~= "all" then
			ScriptManager:StopServerScripts(context.Player)
			return "Got no server scripts."
		end

		ScriptManager:StopServerScripts()
		Output:appendToAll(
			Output.MessageType.Success,
			`{Functions.formatPlayerName(context.Player)} got no server scripts.`
		)
	end)

	--:noLocalScripts
	define("noLocalScripts", function(context)
		ScriptManager:StopLocalScripts(context.Player)
		return "Got no local scripts."
	end)
end
