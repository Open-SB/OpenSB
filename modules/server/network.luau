--!strict

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local services = require("@shared/network/services")
local RequestMethods = require("@shared/network/requestMethods")
local ServerRequestMethod = RequestMethods.Server
local ClientRequestMethod = RequestMethods.Client

local Log = require("@shared/log")
local Functions = require("@shared/functions")
local MLDSA87 = require("@shared/crypto/MlDSA").ML_DSA_87
local MLKEM = require("@shared/crypto/MlKEM").MLKEM_1024
local CSPRNG = require("@shared/crypto/CSPRNG")
local Base64 = require("@shared/crypto/base64")
local Protection = require("@shared/protection")
local PlayerList = require("@shared/playerList")

local Utils = require("@shared/network/utils")

-- add extra entropy
CSPRNG.Instance:GatherEntropy(Utils.generateEntropy())

local dsaServerPrivateKey: buffer = Base64.Decode(buffer.fromstring(_G.dsaServerPrivateKey))
-- local dsaServerPublicKey: buffer = Base64.Decode(buffer.fromstring(_G.dsaServerPublicKey))

local kemServerPrivateKey: buffer = Base64.Decode(buffer.fromstring(_G.kemServerPrivateKey))
-- local kemServerPublicKey: buffer = Base64.Decode(buffer.fromstring(_G.kemServerPublicKey))

local clientNetworkData: {
	[Player]: {
		kemPublicKey: buffer,

		staticKey: buffer,

		nonce: number, -- Last server used nonce, next nonce to use should be this + 1
		lastNonce: number, -- Last nonce client sent, new nonces should always be greater than this one
	},
} =
	{}

local connectedPlayers: { [Player]: boolean } = {} -- We keep track of players that have successfully connected to the remote, so we don't accidentally send stuff to them without them actually listening to the remote
local exchanged: { [Player]: boolean } = {} -- We lock keys after the first handshake
PlayerList.Removed:Connect(function(player: Player)
	clientNetworkData[player] = nil
	connectedPlayers[player] = nil
	exchanged[player] = nil
end)

local Network = {}
Network.attributeName, Network.attributeValue = string.sub(tostring(math.random()), 3), math.random()

local registeredEvents: { [string]: (Player, ...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (Player, ...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local registeredFunctions: { [string]: (Player, ...unknown) -> ...unknown } = {}
function Network:RegisterFunction(name: string, callback: (Player, ...unknown) -> ...unknown)
	if registeredFunctions[name] then
		Log.warn(`Network function "{name}" was overwritten.`)
	end

	registeredFunctions[name] = callback
end

local function encryptAnythingForPlayer(player: Player, data)
	local networkData = clientNetworkData[player]
	assert(networkData, `Failed to get network data for {player}`)

	return Utils.encryptAnything(networkData, data)
end

local function decryptFromPlayerAndVarargs(player: Player, ciphertext, nonce, tag, instanceArray)
	local networkData = clientNetworkData[player]
	assert(networkData, `Failed to get network data for {player}`)

	return Utils.decryptAnythingAndVerify(networkData, ciphertext, nonce, tag, instanceArray)
end

local remote: RemoteFunction, remoteParent: Instance

local function onRequest(player: Player, requestType, ...): ...any
	-- Key exchange and handshake requests should be the only times we return something from remote functions, the only reason we are using them is to prevent logging
	-- When returning something from remote functions we are risking it never getting sent back to the client if the remote function were to get destroyed while the callback is executing
	-- In that case we just allow the client to resend the request (it's also why we are not locking the key here)

	-- We allow them for the handshake because if the remote gets destroyed the client would have to make another handshake to the new remote anyways, and because if we did a client invoke it could get intercepted

	if requestType == ServerRequestMethod.KeyExchange then
		if exchanged[player] then
			local outputSignature = buffer.create(MLDSA87.SigByteLen)
			local messageToSign = buffer.fromstring("alreadyExchanged@" .. os.time()) -- this can be static because of randomness, but still
			local randomness = CSPRNG.RandomBytes(MLDSA87.SigningSeedByteLen)

			local signSuccess = MLDSA87.Sign(
				randomness,
				dsaServerPrivateKey,
				messageToSign,
				Utils.getDsaContext(player),
				outputSignature
			)

			if not signSuccess then
				-- explicitly prevent changing keys & allow client to prevent potential mitm as fast as possible
				return
			end

			return outputSignature, messageToSign
		end

		local kemPublicKey, kemCiphertext = ...

		if type(kemPublicKey) ~= "buffer" or buffer.len(kemPublicKey) ~= Utils.ML_KEM_1024_PUBLIC_KEY_SIZE then
			return
		end

		if type(kemCiphertext) ~= "buffer" or buffer.len(kemCiphertext) ~= Utils.ML_KEM_1024_CIPHERTEXT_SIZE then
			return
		end

		local sharedSecret = MLKEM.Decapsulate(kemServerPrivateKey, kemCiphertext)

		if clientNetworkData[player] == nil then
			clientNetworkData[player] = {
				kemPublicKey = kemPublicKey,
				staticKey = sharedSecret,
				nonce = -1,
				lastNonce = -1,
			}
		end

		local outputSignature = buffer.create(MLDSA87.SigByteLen)
		local messageToSign = buffer.fromstring("exchanged@" .. os.time()) -- this can be static because of randomness, but still
		local randomness = CSPRNG.RandomBytes(MLDSA87.SigningSeedByteLen)

		local signSuccess =
			MLDSA87.Sign(randomness, dsaServerPrivateKey, messageToSign, Utils.getDsaContext(player), outputSignature)

		if not signSuccess then
			return
		end

		exchanged[player] = true

		return outputSignature, messageToSign
	elseif requestType == ServerRequestMethod.Handshake then
		-- if the player has not exchanged keys, or has already sent a handshake, return
		if not exchanged[player] or connectedPlayers[player] then
			return
		end

		local check = decryptFromPlayerAndVarargs(player, ...)
		if type(check) ~= "string" then
			return
		end

		connectedPlayers[player] = true -- We will assume that the handshake succeeds for the client aswell

		return encryptAnythingForPlayer(player, check)
	elseif requestType == ServerRequestMethod.Event then
		-- Minimize the yielding time for the client if the server is calculating stuff
		task.spawn(function(...)
			local decryptedData: {
				id: string,
				eventName: string,
				arguments: { any },
			}? =
				decryptFromPlayerAndVarargs(player, ...)
			if
				type(decryptedData) ~= "table"
				or type(decryptedData.eventName) ~= "string"
				or type(decryptedData.arguments) ~= "table"
			then
				return
			end

			local callback = registeredEvents[decryptedData.eventName]
			if not callback then
				return
			end

			callback(player, unpack(decryptedData.arguments))
		end, ...)
	elseif requestType == ServerRequestMethod.Invoke then
		-- Minimize the yielding time for the client if the server is calculating stuff
		task.spawn(function(...)
			local decryptedData: {
				id: string,
				functionName: string,
				arguments: { any },
			}? =
				decryptFromPlayerAndVarargs(player, ...)

			if
				type(decryptedData) ~= "table"
				or type(decryptedData.id) ~= "string"
				or type(decryptedData.functionName) ~= "string"
				or type(decryptedData.arguments) ~= "table"
			then
				return
			end

			local callback = registeredFunctions[decryptedData.functionName]
			if not callback then
				return
			end

			(function(...)
				while not connectedPlayers[player] or not remote or remote.Parent ~= remoteParent do
					task.wait()
				end

				remote:InvokeClient(
					player,
					ClientRequestMethod.InvokeResult,
					encryptAnythingForPlayer(player, { id = decryptedData.id, arguments = { ... } })
				)
			end)(callback(player, unpack(decryptedData.arguments)))
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
			ClientRequestMethod.Event,
			encryptAnythingForPlayer(player, {
				eventName = eventName,
				arguments = { ... },
			})
		)
	end, ...)
end

function Network:FireAllClients(eventName: string, ...: any)
	for _, player: Player in ipairs(Players:GetPlayers()) do
		Network:FireClient(player, eventName, ...)
	end
end

function Network:Init()
	local lastRemoteFix = os.clock() -- We keep track of this so we can recreate the remote every 5 seconds, incase the remote get deleted on someones client
	local function fixRemote()
		lastRemoteFix = os.clock()

		if remote then
			task.delay(0, function(oldRemote)
				Protection.remove(oldRemote)
				oldRemote:Destroy()
			end, remote)
		end

		table.clear(connectedPlayers)

		remote = Instance.new("RemoteFunction")
		remote.Name = Functions.randomInstanceName()
		remote.Archivable = false
		remote:SetAttribute(Network.attributeName, Network.attributeValue)

		Protection.add(remote, "write")

		remoteParent = services[math.random(1, #services)]
		remote.Parent = remoteParent
	end

	fixRemote()
	remote.OnServerInvoke = onRequest

	-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
	local args: any = table.create(80, task.defer)
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
end

return Network
