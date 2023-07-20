--!strict
local __start = os.clock()

-- Localize variables and remove environment for security
local game = game
local task = task
local script = script
local setfenv = setfenv
local os = os
local math = math
local table = table
local Instance = Instance
local string = string
local pcall = pcall
local unpack = unpack
local tostring = tostring
local coroutine = coroutine
local ipairs = ipairs

-- These are replaced later
local _print = print
local _warn = warn

setfenv(1, {})

local debugEnabled = game:GetService("RunService"):IsStudio()
local function debug(...: any)
	if debugEnabled then
		game:GetService("TestService"):Message("[SB] " .. table.concat({ ... }, " "))
	end
end

local function print(...: any)
	_print("[SB]", ...)
end

local function warn(...: any)
	_warn("[SB]", ...)
end

local function randomString(): string
	return tostring(math.random())
end

-- Fetch assets and destroy script
debug("Fetching assets")

local sbClient = script:WaitForChild("client"):Clone()

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			script:Destroy()
			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

-- Services and modules
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Network = {}

debug("Loading modules")

-- Network
do
	Network.attributeName, Network.attributeValue = string.sub(tostring(math.random()), 3), math.random()

	local registeredEvents: { [string]: (...unknown) -> nil } = {}
	function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
		if registeredEvents[name] then
			warn(`Network event "{name}" was overwritten`)
		end

		registeredEvents[name] = callback
	end

	local registeredFunctions: { [string]: (...unknown) -> ...unknown } = {}
	function Network:RegisterFunction(name: string, callback: (...unknown) -> ...unknown)
		if registeredFunctions[name] then
			warn(`Network function "{name}" was overwritten`)
		end

		registeredFunctions[name] = callback
	end

	-- TODO: key system

	local connectedPlayers: { [Player]: boolean } = {} -- We keep track of players that have successfully connected to the remote, so we don't accidentally send stuff to them without them actually listening to the remote
	local function OnServerInvoke(player: Player) end

	local lastNetworkFolderFix = os.clock() -- We keep track of this so we can recreate the remotes every 5 seconds, incase the remotes get deleted on someones client
	local networkFolder, remoteEvent, remoteFunction

	function Network:FireClient(player: Player, ...: any)
		task.spawn(function(...)
			while
				not connectedPlayers[player]
				or not networkFolder
				or not remoteEvent
				or networkFolder.Parent ~= ReplicatedStorage
				or remoteEvent.Parent ~= networkFolder
			do
				task.wait()
			end

			--remoteEvent:FireClient(player, ...)
		end, ...)
	end

	function Network:FireAllClients(...: any)
		for _, player: Player in ipairs(Players:GetPlayers()) do
			Network:FireClient(player, ...)
		end
	end

	local function fixNetworkFolder()
		lastNetworkFolderFix = os.clock()

		if networkFolder then
			task.delay(0, game.Destroy, networkFolder)
		end

		if remoteEvent then
			task.delay(0, game.Destroy, remoteEvent)
		end

		if remoteFunction then
			task.delay(0, game.Destroy, remoteFunction)
		end

		networkFolder = Instance.new("Folder")
		networkFolder.Name = randomString()
		networkFolder.Archivable = false
		networkFolder:SetAttribute(Network.attributeName, Network.attributeValue)

		remoteEvent = Instance.new("RemoteEvent")
		remoteEvent.Name = randomString()
		remoteEvent.Archivable = false
		remoteEvent.Parent = networkFolder

		remoteFunction = Instance.new("RemoteFunction")
		remoteFunction.Name = randomString()
		remoteFunction.Archivable = false
		remoteFunction.Parent = networkFolder

		networkFolder.Parent = ReplicatedStorage
	end

	fixNetworkFolder()
	remoteFunction.OnServerInvoke = OnServerInvoke

	-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
	local args = table.create(80, task.defer)
	table.insert(args, function()
		if
			not networkFolder
			or networkFolder.Parent ~= ReplicatedStorage
			or remoteEvent.Parent ~= networkFolder
			or remoteFunction.Parent ~= networkFolder
			or networkFolder:GetAttribute(Network.attributeName) ~= Network.attributeValue
			or #networkFolder:GetDescendants() > 2
			or os.clock() - lastNetworkFolderFix >= 5
		then
			fixNetworkFolder()
		end

		remoteFunction.OnServerInvoke = OnServerInvoke

		-- Prevent fakes
		for _, child in ipairs(ReplicatedStorage:GetChildren()) do
			if child.ClassName ~= "Folder" or child == networkFolder then
				continue
			end

			if child:GetAttribute(Network.attributeName) == Network.attributeValue then
				child:SetAttribute(Network.attributeName, nil)
				pcall(game.Destroy, child)
			end
		end
	end)

	RunService.PostSimulation:Connect(function()
		pcall(unpack(args))
	end)
end

debug("Loading systems")

-- Player system
do
	local function disconnectPlayer(player: Player) end

	local function connectPlayer(player: Player)
		debug(`Checking if {player} can join...`)

		if not RunService:IsStudio() and player.AccountAge < 7 then
			debug(`{player}'s account age is too young (<7).`)
			player:Kick(`Your account age has to be atleast one week old to play this game.`)

			-- TODO: Alert to others why they couldnt join

			return
		end

		debug(`Checking ban on {player}...`)
		-- TODO: Ban check

		do
			debug(`Loading SB client on {player}...`)

			local backpack = Instance.new("Backpack")
			backpack.Name = randomString()
			backpack.Archivable = false

			local newClient = sbClient:Clone()
			newClient.Name = randomString()
			newClient.Archivable = false
			newClient.Parent = backpack

			-- Tranfer the remote attributes to find the remotes
			newClient:SetAttribute(Network.attributeName, Network.attributeValue)

			backpack.Parent = player
			task.defer(
				function() -- This wont work as well if the local script contains children, as they might go missing, and we are going to need children so this will change
					backpack:Destroy()
					newClient:Destroy()
				end
			)
		end
	end

	Players.PlayerAdded:Connect(connectPlayer)
	Players.PlayerRemoving:Connect(disconnectPlayer)

	for _, player: Player in ipairs(Players:GetPlayers()) do
		task.spawn(connectPlayer, player)
	end
end

-- Finalize
debug("Finalizing...")

Players.CharacterAutoLoads = true

debug(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)
