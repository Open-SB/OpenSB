local World = require("server/world")

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
end
