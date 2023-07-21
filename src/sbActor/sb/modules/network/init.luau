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

local services = table.clone(require(script:WaitForChild("services")))

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

local lastRemoteFix = os.clock() -- We keep track of this so we can recreate the remote every 5 seconds, incase the remote get deleted on someones client
local remote, remoteParent

function Network:FireClient(player: Player, ...: any)
	task.spawn(function(...)
		while not connectedPlayers[player] or not remote or remote.Parent ~= remoteParent do
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

local function fixRemote()
	lastRemoteFix = os.clock()

	if remote then
		task.delay(0, game.Destroy, remote)
	end

	remote = Instance.new("RemoteFunction")
	remote.Name = Functions.randomInstanceName()
	remote.Archivable = false
	remote:SetAttribute(Network.attributeName, Network.attributeValue)

	remoteParent = services[math.random(1, #services)]
	remote.Parent = remoteParent
end

fixRemote()
remote.OnServerInvoke = OnServerInvoke

-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
local args = table.create(80, task.defer)
table.insert(args, function()
	if
		not remote
		or remote.Parent ~= remoteParent
		or remote:GetAttribute(Network.attributeName) ~= Network.attributeValue
		or #remote:GetChildren() > 2
		or os.clock() - lastRemoteFix >= 5
	then
		fixRemote()
	end

	remote.OnServerInvoke = OnServerInvoke
end)

RunService.PostSimulation:Connect(function()
	pcall(unpack(args))
end)

return { Network }
