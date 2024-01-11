local Instance = Instance
local Enum = Enum
local Vector3 = Vector3
local Color3 = Color3
local workspace = workspace

local Players = game:GetService("Players")

local World = {}
World.Base = nil

function World:RemoveBase()
	if not self.Base then
		return
	end

	self.Base:Destroy()
	self.Base = nil
end

function World:AddBase()
	self:RemoveBase()

	local base = Instance.new("Part")
	base.Name = "Base"
	base.Anchored = true
	base.CFrame = CFrame.new(0, -1.5, 0)
	base.Size = Vector3.new(512, 3, 512)
	base.Material = Enum.Material.Grass
	base.Color = Color3.fromRGB(31, 128, 29)

	self.Base = base
	base.Parent = workspace
end

function World:Clear()
	for _, child in ipairs(workspace:GetChildren()) do
		if child.ClassName == "Camera" then
			child:ClearAllChildren()
		elseif child.ClassName == "Terrain" then
			child:ClearAllChildren()
			child:Clear()
		else
			if child.ClassName == "Model" and Players:GetPlayerFromCharacter(child) then
				continue
			end

			if child.ClassName == "Script" or child == World.Base then
				continue
			end

			child:Destroy()
		end
	end
end

function World:Init()
	self:Clear()
	self:AddBase()
end

return World
