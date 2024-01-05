-- A list of possible services that the network remotes can be parented to.

if _G.DEV then
	-- While in development, it might be helpful to know where the remotes are located at.
	return { game:GetService("ReplicatedStorage") }
end

-- Some services are commented out because they either might break some scripts, or the services clone its children in some cases (StarterGui for example).
return {
	--game:GetService("Chat"),
	game:GetService("FriendService"),
	game:GetService("InsertService"),
	game:GetService("JointsService"),
	--game:GetService("Lighting"),
	game:GetService("LocalizationService"),
	game:GetService("MarketplaceService"),
	game:GetService("MaterialService"),
	--game:GetService("Players"),
	game:GetService("ProximityPromptService"),
	game:GetService("ReplicatedStorage"),
	--game:GetService("SoundService"),
	--game:GetService("StarterGui"),
	--game:GetService("StarterPack"),
	--game:GetService("StarterPlayer"),
	--game:GetService("Teams"),
	game:GetService("TestService"),
	game:GetService("TextChatService"),
	game:GetService("VoiceChatService"),
	--game:GetService("Workspace"),
}
