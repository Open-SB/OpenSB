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
local type = type

setfenv(1, {})

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")

local Modules = require(script.Parent)
local services = table.clone(require(script:WaitForChild("services")))
script = nil

local Log = Modules.require("log")
local Functions = Modules.require("functions")
local HashLib = Modules.require("hashLib")

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

local keys: { [Player]: string } = {}
local usedHashes: { [Player]: { [string]: boolean } } = {} -- Prevent replay attacks

local function isValidRequestKey(player: Player, requestKey): boolean
	if type(requestKey) ~= "table" then
		return false
	end

	local hash, salt = requestKey[1], requestKey[2]
	if type(hash) ~= "string" or type(salt) ~= "string" then
		return false
	end

	local playerUsedHashes = usedHashes[player]
	if not playerUsedHashes then
		playerUsedHashes = {}
		usedHashes[player] = playerUsedHashes
	end

	if playerUsedHashes[hash] then
		return false
	end

	if hash == HashLib.hmac(HashLib.sha256, keys[player], salt) then
		playerUsedHashes[hash] = true

		return true
	end

	return false
end

local function generateRequestKey(player: Player): { string }
	local playerUsedHashes = usedHashes[player]
	if not playerUsedHashes then
		playerUsedHashes = {}
		usedHashes[player] = playerUsedHashes
	end

	local salt = Functions.randomString(64)
	local hash = HashLib.hmac(HashLib.sha256, keys[player], salt)

	if playerUsedHashes[hash] then -- It's very unlikely this would ever happen, but ¯\_(ツ)_/¯
		return generateRequestKey(player)
	end

	playerUsedHashes[hash] = true
	return { hash, salt }
end

local connectedPlayers: { [Player]: boolean } = {} -- We keep track of players that have successfully connected to the remote, so we don't accidentally send stuff to them without them actually listening to the remote
local lockedKeys: { [Player]: boolean } = {} -- We lock keys after the first handshake

local remote: RemoteFunction, remoteParent: Instance

local function onRequest(player: Player, requestType, requestKey, ...)
	-- Key exchange and handshake requests should be the only times we return something from remote functions, the only reason we are using them is to prevent logging
	-- When returning something from remote functions we are risking it never getting sent back to the client if the remote function were to get destroyed while the callback is executing
	-- In that case we just allow the client to resend the request (it's also why we are not locking the key here)

	-- We allow them for the handshake because if the remote gets destroyed the client would have to make another handshake to the new remote anyways, and because if we did a client invoke it could get intercepted

	if requestType == 0 then -- Key exchange
		if lockedKeys[player] then
			return
		end

		-- TODO: Sign key with asymmetric keys (public private keys), so the client can verify the servers identity (and prevent man in the middle attacks)

		local key = Functions.randomString(64) -- 64 is the blocksize for sha256, if it's not exactly 64 then HMAC would either extend the key to be 64 characters, or hash the key to become 64 characters
		keys[player] = key

		return key
	elseif requestType == 1 then -- Handshake
		-- Basic handshake to verify the servers identity, is not 100% immune to man in the middle attacks, but checking the time it took for the request to complete compared to your ping should help

		if not isValidRequestKey(player, requestKey) then
			return
		end

		connectedPlayers[player] = true -- We will assume that the handshake succeeds for the client aswell
		lockedKeys[player] = true

		return generateRequestKey(player)
	elseif requestType == 2 then -- Event
		-- Minimize the yielding time for the client if the server is calculating stuff
		task.spawn(function(eventName, ...)
			local callback = registeredEvents[eventName]
			if not callback then
				return
			end

			if not isValidRequestKey(player, requestKey) then
				return
			end

			callback(player, ...)
		end, ...)
	elseif requestType == 3 then -- Invoke
		-- Minimize the yielding time for the client if the server is calculating stuff
		task.spawn(function(id, functionName, ...)
			local callback = registeredFunctions[functionName]
			if not callback then
				return
			end

			if not isValidRequestKey(player, requestKey) then
				return
			end

			(function(...)
				while not connectedPlayers[player] or not remote or remote.Parent ~= remoteParent do
					task.wait()
				end

				remote:InvokeClient(
					player,
					1, -- Invoke result
					generateRequestKey(player),
					id,
					...
				)
			end)(callback(player, ...))
		end, ...)
	end

	return
end

function Network:FireClient(player: Player, eventName: string, ...: any)
	task.spawn(function(...)
		while not connectedPlayers[player] or not remote or remote.Parent ~= remoteParent do
			task.wait()
		end

		remote:InvokeClient(
			player,
			0, -- Event
			generateRequestKey(),
			eventName,
			...
		)
	end, ...)
end

function Network:FireAllClients(eventName: string, ...: any)
	for _, player: Player in ipairs(Players:GetPlayers()) do
		Network:FireClient(player, eventName, ...)
	end
end

local lastRemoteFix = os.clock() -- We keep track of this so we can recreate the remote every 5 seconds, incase the remote get deleted on someones client
local function fixRemote()
	lastRemoteFix = os.clock()

	if remote then
		task.delay(0, game.Destroy, remote)
	end

	table.clear(connectedPlayers)

	remote = Instance.new("RemoteFunction")
	remote.Name = Functions.randomInstanceName()
	remote.Archivable = false
	remote:SetAttribute(Network.attributeName, Network.attributeValue)

	remoteParent = services[math.random(1, #services)]
	remote.Parent = remoteParent
end

fixRemote()
remote.OnServerInvoke = onRequest

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

	remote.OnServerInvoke = onRequest
end)

RunService.PostSimulation:Connect(function()
	pcall(unpack(args))
end)

return { Network }
