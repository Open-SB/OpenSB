--!nonstrict
--	// FileName: ClearMessages.lua
--	// Written by: TheGamer101
--	// Description: Command to switch channel.

local chatFolder = script.Parent.Parent.Parent

local util = require(script.Parent:WaitForChild("Util"))

local ChatLocalization = nil
-- ROBLOX FIXME: Can we define ClientChatModules statically in the project config
pcall(function()
	ChatLocalization = require(chatFolder.ClientChatModules.ChatLocalization :: any)
end)
if ChatLocalization == nil then
	ChatLocalization = {
		Get = function(self, key, default)
			return default
		end,
	}
end

function ProcessMessage(message, ChatWindow, ChatSettings)
	if string.sub(message, 1, 3):lower() ~= "/c " then
		return false
	end

	local channelName = string.sub(message, 4)

	local targetChannel = ChatWindow:GetChannel(channelName)
	if targetChannel then
		ChatWindow:SwitchCurrentChannel(channelName)
		if not ChatSettings.ShowChannelsBar then
			local currentChannel = ChatWindow:GetCurrentChannel()
			if currentChannel then
				util:SendSystemMessageToSelf(
					string.gsub(
						ChatLocalization:Get(
							"GameChat_SwitchChannel_NowInChannel",
							string.format("You are now chatting in channel: '%s'", channelName),
							{ RBX_NAME = channelName }
						),
						"{RBX_NAME}",
						channelName
					),
					targetChannel,
					{}
				)
			end
		end
	else
		local currentChannel = ChatWindow:GetCurrentChannel()
		if currentChannel then
			util:SendSystemMessageToSelf(
				string.gsub(
					ChatLocalization:Get(
						"GameChat_SwitchChannel_NotInChannel",
						string.format("You are not in channel: '%s'", channelName),
						{ RBX_NAME = channelName }
					),
					"{RBX_NAME}",
					channelName
				),
				currentChannel,
				{ ChatColor = Color3.fromRGB(245, 50, 50) }
			)
		end
	end

	return true
end

return {
	[util.KEY_COMMAND_PROCESSOR_TYPE] = util.COMPLETED_MESSAGE_PROCESSOR,
	[util.KEY_PROCESSOR_FUNCTION] = ProcessMessage,
}
