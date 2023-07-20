--!strict
local setfenv = setfenv
local script = script
local require = require
local game = game
local tostring = tostring
local math = math
local string = string
local os = os
local Instance = Instance
local table = table
local task = task
local pcall = pcall
local unpack = unpack
local ipairs = ipairs

setfenv(1, {})

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

local Modules = require(script.Parent)
script = nil

local Log = Modules.require("log")
local Functions = Modules.require("functions")

local Network = {}

Network.attributeName, Network.attributeValue = string.sub(tostring(math.random()), 3), math.random()

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local registeredFunctions: { [string]: (...unknown) -> ...unknown } = {}
function Network:RegisterFunction(name: string, callback: (...unknown) -> ...unknown)
	if registeredFunctions[name] then
		Log.warn(`Network function "{name}" was overwritten.`)
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
	networkFolder.Name = Functions.randomInstanceName()
	networkFolder.Archivable = false
	networkFolder:SetAttribute(Network.attributeName, Network.attributeValue)

	remoteEvent = Instance.new("RemoteEvent")
	remoteEvent.Name = Functions.randomInstanceName()
	remoteEvent.Archivable = false
	remoteEvent.Parent = networkFolder

	remoteFunction = Instance.new("RemoteFunction")
	remoteFunction.Name = Functions.randomInstanceName()
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

return { Network }
