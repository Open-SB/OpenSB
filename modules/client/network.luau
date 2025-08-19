--!strict

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local services = require("@shared/network/services")
local RequestMethods = require("@shared/network/requestMethods")
local ServerRequestMethod = RequestMethods.Server
local ClientRequestMethod = RequestMethods.Client

local Log = require("@shared/log")
local Functions = require("@shared/functions")
local Signal = require("@shared/signal")
local MLDSA87 = require("@shared/crypto/MlDSA").ML_DSA_87
local MLKEM1024 = require("@shared/crypto/MlKEM").MLKEM_1024
local AEAD = require("@shared/crypto/AEAD")
local CSPRNG = require("@shared/crypto/CSPRNG")
local Base64 = require("@shared/crypto/base64")
local Encoding = require("@shared/network/encoding")
local Utils = require("@shared/network/utils")

local localPlayer = Players.LocalPlayer
local attributeName, attributeValue

local Network = {}

local dsaServerPublicKey: buffer = Base64.Decode(buffer.fromstring(_G.dsaServerPublicKey))
local kemServerPublicKey: buffer = Base64.Decode(buffer.fromstring(_G.kemServerPublicKey))
local networkStaticValue: buffer? = nil

-- add extra entropy
do
	local HttpService = game:GetService("HttpService")
	local seed = ""

	for _ = 1, 128 do
		seed ..= HttpService:GenerateGUID(false)
	end

	CSPRNG.Instance:GatherEntropy(buffer.fromstring(seed))
end

local kemClientPublicKey: buffer, _kemClientPrivateKey: buffer = MLKEM1024.GenerateKeys()

local clientNonce = -1 -- Last client used nonce, next nonce to use should be this + 1
local lastServerNonce = -1 -- Last nonce server sent, new nonces should always be greater than this one

local _hasExchanged = false

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local function padNonce(nonce: number): buffer
	local buf = buffer.create(12)
	buffer.writeu32(buf, 0, nonce)

	return buf
end

local function encryptBuffer(data: buffer): (buffer, number, buffer)
	clientNonce += 1

	local ciphertext, tag =
		AEAD.Encrypt(data, assert(networkStaticValue, "network static value not obtained yet"), padNonce(clientNonce))
	return ciphertext, clientNonce, tag
end

local function encryptAnything(data: any): (buffer, number, buffer, { Instance })
	local encodedData, instancesArray = Encoding.encode(data)
	local ciphertext, nonce, tag = encryptBuffer(encodedData)

	return ciphertext, nonce, tag, instancesArray
end

local function decryptBuffer(ciphertext: buffer, nonce: number, tag: buffer): buffer
	return assert(
		AEAD.Decrypt(
			ciphertext,
			assert(networkStaticValue, "network static value not obtained yet"),
			padNonce(nonce),
			tag
		),
		"failed decrypting data with aead"
	)
end

local function decryptAnything(ciphertext: buffer, nonce: number, tag: buffer, instanceArray: { Instance }): any
	return Encoding.decode(decryptBuffer(ciphertext, nonce, tag), instanceArray)
end

local function decryptWithUnknownVarargs(ciphertext, nonce, tag, instanceArray): any?
	if
		type(ciphertext) ~= "buffer"
		or type(nonce) ~= "number"
		or type(tag) ~= "buffer"
		or type(instanceArray) ~= "table"
	then
		return nil
	end

	if nonce <= lastServerNonce then
		-- This is a replayed nonce
		return nil
	end

	local data = decryptAnything(ciphertext, nonce, tag, instanceArray :: { Instance })
	lastServerNonce = nonce

	return data
end

local remotes: { [RemoteFunction]: Instance } = {}
local invokeResults: { [string]: BindableEvent } = {}

local function onRequest(requestType, ...)
	if requestType == ClientRequestMethod.Event then
		-- Minimize the yielding time for the server if the client is calculating stuff
		task.spawn(function(...)
			local decryptedData = decryptWithUnknownVarargs(...)
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

			callback(unpack(decryptedData.arguments))
		end, ...)
	elseif requestType == ClientRequestMethod.InvokeResult then
		-- Minimize the yielding time for the server if the client is calculating stuff
		task.spawn(function(...)
			local decryptedData = decryptWithUnknownVarargs(...)
			if
				type(decryptedData) ~= "table"
				or type(decryptedData.id) ~= "string"
				or type(decryptedData.arguments) ~= "table"
			then
				return
			end

			local signal = invokeResults[decryptedData.id]
			if not signal then
				return
			end

			signal:Fire(unpack(decryptedData.arguments))
		end, ...)
	end
end

function Network:FireServer(eventName: string, ...)
	task.spawn(function(...)
		while next(remotes) == nil do
			task.wait()
		end

		for remote, _ in remotes do
			task.spawn(
				remote.InvokeServer,
				remote,
				ServerRequestMethod.Event,
				encryptAnything({ eventName = eventName, arguments = { ... } })
			)
		end
	end, ...)
end

function Network:InvokeServer(functionName: string, ...)
	local id = nil
	repeat
		id = Functions.randomString(8)
	until not invokeResults[id]

	local signal = Signal.new()
	invokeResults[id] = signal

	while next(remotes) == nil do
		task.wait()
	end

	for remote, _ in remotes do
		task.spawn(
			remote.InvokeServer,
			remote,
			ServerRequestMethod.Invoke,
			encryptAnything({
				id = id,
				functionName = functionName,
				arguments = { ... },
			})
		)
	end

	return (function(signal, ...)
		invokeResults[id] = nil
		signal:Destroy()

		return ...
	end)(signal, signal:Wait())
end

local function connectRemote(service: Instance, remote: RemoteFunction)
	if remote:GetAttribute(attributeName) ~= attributeValue then
		return
	end

	if not networkStaticValue then
		local ciphertext, sharedSecret = MLKEM1024.Encapsulate(kemServerPublicKey, CSPRNG.RandomBytes(32))

		local messageSignature, message =
			remote:InvokeServer(ServerRequestMethod.KeyExchange, kemClientPublicKey, ciphertext)

		if type(messageSignature) ~= "buffer" or type(message) ~= "buffer" then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (invalid arguments: expected buffer, buffer but got {typeof(
					messageSignature
				)}, {typeof(message)}`
			)
		end

		if buffer.len(messageSignature) ~= MLDSA87.SigByteLen then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (buffer length is not {MLDSA87.SigByteLen}, got {buffer.len(
					messageSignature
				)})`
			)
		end

		if not MLDSA87.Verify(dsaServerPublicKey, message, Utils.getDsaContext(localPlayer), messageSignature) then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (invalid server public key signature)`
			)
		end

		local messageSplit = string.split(buffer.tostring(message), "@")
		local messageType: "alreadyExchanged" | "exchanged" = messageSplit[1] :: any

		if messageType == "alreadyExchanged" then
			localPlayer:Kick(
				"[SB Client] A localscript succeeded a key exchange on your client; try rejoining. (an mitm attack was prevented)"
			)

			return
		end

		networkStaticValue = sharedSecret
	end

	local check = CSPRNG.RandomString(32)

	local ciphertext, nonce, tag, instanceArray =
		remote:InvokeServer(ServerRequestMethod.Handshake, encryptAnything(check))

	local function reexchange()
		networkStaticValue = nil
		return connectRemote(service, remote)
	end

	if
		type(ciphertext) ~= "buffer"
		or type(nonce) ~= "number"
		or type(tag) ~= "buffer"
		or type(instanceArray) ~= "table"
	then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (some values are invalid)`)
		return reexchange()
	end

	local newCheck = decryptWithUnknownVarargs(ciphertext, nonce, tag, instanceArray)
	if not newCheck then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (decryption failed)`)
		return reexchange()
	end

	hasExchanged = true -- If decryption is sucessful, then we've exchanged on the server

	if newCheck ~= check then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (invalid check)`)
		return
	end

	remotes[remote] = service
	remote.OnClientInvoke = onRequest
end

function Network:Init(attribute: {})
	attributeName, attributeValue = unpack(attribute)

	for _, service in ipairs(services) do
		service.ChildAdded:Connect(function(child)
			if child.ClassName == "RemoteFunction" then
				connectRemote(service, child :: RemoteFunction)
			end
		end)

		for _, child in ipairs(service:GetChildren()) do
			if child.ClassName == "RemoteFunction" then
				task.spawn(connectRemote, service, child :: RemoteFunction)
			end
		end
	end

	-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
	local args: any = table.create(80, task.defer)
	table.insert(args, function()
		for remote, service in remotes do
			if remote.Parent ~= service then
				remotes[remote] = nil

				continue
			end

			remote.OnClientInvoke = onRequest
		end
	end)

	RunService.PostSimulation:Connect(function()
		pcall(unpack(args))
	end)
end

return Network
