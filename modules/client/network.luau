--!strict

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local services = require("@shared/network/services")
local RequestMethods = require("@shared/network/requestMethods")
local ServerRequestMethod = RequestMethods.Server
local ClientRequestMethod = RequestMethods.Client

local Log = require("@shared/log")
local Functions = require("@shared/functions")
local HashLib = require("@shared/hashLib")
local Signal = require("@shared/signal")
local EdDSA = require("@shared/crypto/EdDSA")
local Base64 = require("@shared/crypto/base64")
local Blake3 = require("@shared/crypto/blake3")
local AEAD = require("@shared/crypto/AEAD")
local Encoding = require("@shared/network/encoding")

local MaskedX25519 = EdDSA.MaskedX25519

local localPlayer = Players.LocalPlayer
local attributeName, attributeValue

local Network = {}

local serverPublicKey: buffer = Base64.Decode(buffer.fromstring(_G.serverPublicKey))
local maskedServerPublicKey: buffer? = nil
local networkStaticValue: buffer? = nil

local clientPrivateKey: buffer = EdDSA.CSPRNG.Ed25519Random()
local clientPublicKey: buffer = EdDSA.PublicKey(clientPrivateKey)

local maskedClientPrivateKey = MaskedX25519.Mask(clientPrivateKey)
local maskedClientPublicKey = MaskedX25519.PublicKey(maskedClientPrivateKey)

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local key: string?
local keyLocked = false
local usedHashes: { [string]: boolean } = {} -- Prevent replay attacks

local function isValidRequestKey(requestKey): boolean
	if type(requestKey) ~= "table" then
		return false
	end

	local hash, salt = requestKey[1], requestKey[2]
	if type(hash) ~= "string" or type(salt) ~= "string" then
		return false
	end

	if usedHashes[hash] then
		return false
	end

	if hash == HashLib.hmac(HashLib.sha256, key, salt) then
		usedHashes[hash] = true

		return true
	end

	return false
end

local function generateRequestKey(): { string }
	while key == nil do
		task.wait()
	end

	local salt = Functions.randomString(64)
	local hash = HashLib.hmac(HashLib.sha256, key, salt)

	if usedHashes[hash] then -- It's very unlikely this would ever happen, but ¯\_(ツ)_/¯
		return generateRequestKey()
	end

	usedHashes[hash] = true
	return { hash, salt }
end

local function encryptBuffer(data: buffer): (buffer, buffer)
	local ciphertext, tag = AEAD.Encrypt(
		data,
		assert(networkStaticValue, "network static value not obtained yet"),
		Blake3.Digest(buffer.fromstring(tostring(assert(key))), 12)
	)
	return ciphertext, tag
end

local function encryptAnything(data: any): (buffer, buffer, { Instance })
	local encodedData, instancesArray = Encoding.encode(data)
	local ciphertext, tag = encryptBuffer(encodedData)

	return ciphertext, tag, instancesArray
end

local function decryptBuffer(ciphertext: buffer, tag: buffer): buffer
	local result = assert(
		AEAD.Decrypt(
			ciphertext,
			assert(networkStaticValue, "network static value not obtained yet"),
			Blake3.Digest(buffer.fromstring(tostring(assert(key))), 12),
			tag
		),
		"failed decrypting data with aead"
	)

	return result
end

local function decryptAnything(ciphertext: buffer, tag: buffer, instanceArray: { Instance })
	return Encoding.decode(decryptBuffer(ciphertext, tag), instanceArray)
end

local function decryptWithUnknownVarargs(ciphertext, tag, instanceArray): any?
	if typeof(ciphertext) ~= "buffer" or typeof(tag) ~= "buffer" or typeof(instanceArray) ~= "table" then
		return nil
	end

	return decryptAnything(ciphertext, tag, instanceArray :: { Instance })
end

local remotes: { [RemoteFunction]: Instance } = {}
local invokeResults: { [string]: BindableEvent } = {}

local function onRequest(requestType, requestKey, ...)
	if requestType == ClientRequestMethod.Event then
		-- Minimize the yielding time for the server if the client is calculating stuff
		task.spawn(function(...)
			if not isValidRequestKey(requestKey) then
				return
			end

			local decryptedData: {
				eventName: string,
				arguments: { any },
			} = decryptWithUnknownVarargs(...)

			if not decryptedData then
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
			if not isValidRequestKey(requestKey) then
				return
			end

			local decryptedData: {
				id: string,
				arguments: { any },
			} = decryptWithUnknownVarargs(...)

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
		while keyLocked ~= true do
			task.wait()
		end

		local requestKey = generateRequestKey()
		while next(remotes) == nil do
			task.wait()
		end

		for remote, _ in remotes do
			task.spawn(
				remote.InvokeServer,
				remote,
				ServerRequestMethod.Event,
				requestKey,
				encryptAnything({ eventName = eventName, arguments = { ... } })
			)
		end
	end, ...)
end

function Network:InvokeServer(functionName: string, ...)
	while keyLocked ~= true do
		task.wait()
	end

	local requestKey, id = generateRequestKey(), nil

	repeat
		id = Functions.randomString(8)
	until invokeResults[id] == nil

	local signal = Signal.new()
	invokeResults[id] = signal

	while next(remotes) == nil do
		task.wait()
	end

	for remote, _ in remotes do
		local a, b, c = encryptAnything({
			id = id,
			functionName = functionName,
			arguments = { ... },
		})

		task.spawn(remote.InvokeServer, remote, ServerRequestMethod.Invoke, requestKey, a, b, c)
	end

	return (function(...)
		invokeResults[id] = nil
		signal:Destroy()

		return ...
	end)(signal:Wait())
end

local function connectRemote(service: Instance, remote: RemoteFunction)
	if remote:GetAttribute(attributeName) ~= attributeValue then
		return
	end

	if not key then
		-- TODO: Check signature of key

		-- We check if the timing is above your ping * 5, as it would take at minimum your ping * 6 to do a man in the middle attack.
		-- Even if this check fails, it would get rechecked the next time the remote refits.
		-- (Not the most reliable way of detecting a mitm attack.)

		-- local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
		local newKey, returnedPublicKeyMasked, signature, returnedPublicKeyMaskedSignature =
			remote:InvokeServer(ServerRequestMethod.KeyExchange, maskedClientPublicKey)

		if
			typeof(newKey) ~= "string"
			or typeof(returnedPublicKeyMasked) ~= "buffer"
			or typeof(signature) ~= "buffer"
		then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (invalid arguments: expected string, buffer, buffer, but got {typeof(
					newKey
				)} {typeof(returnedPublicKeyMasked)} {typeof(signature)})`
			)
		end

		if buffer.len(returnedPublicKeyMasked) ~= 32 then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (buffer length is not 32, got {buffer.len(
					returnedPublicKeyMasked
				)})`
			)
		end

		if not EdDSA.Verify(serverPublicKey, returnedPublicKeyMasked, returnedPublicKeyMaskedSignature) then
			return Log.warn(`Key exchange failed on remote "{remote:GetFullName()}" (invalid key signature)`)
		end

		if not EdDSA.Verify(serverPublicKey, buffer.fromstring(newKey), signature) then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (invalid server public key signature)`
			)
		end

		-- ensure server does not try and screw us over
		if maskedServerPublicKey and maskedServerPublicKey ~= returnedPublicKeyMasked then
			return Log.warn(
				"Key exchange failed! Server already gave one masked public key, and attempted to change it."
			)
		end

		-- local requestTime = os.clock() - requestStart

		-- if ping > 0 and requestTime > ping * 5 then
		-- 	return Log.warn(
		-- 		`Key exchange failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping * 2}])`
		-- 	)
		-- end

		maskedServerPublicKey = returnedPublicKeyMasked
		local staticSecret, _clientEphemeral =
			MaskedX25519.Exchange(maskedClientPrivateKey, maskedServerPublicKey :: buffer)

		networkStaticValue = Blake3.Digest(staticSecret, 32)

		key = newKey
	end

	-- local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
	local ciphertext, tag, instanceArray, keySignature =
		remote:InvokeServer(ServerRequestMethod.Handshake, generateRequestKey())
	-- local requestTime = os.clock() - requestStart

	if typeof(ciphertext) ~= "buffer" or typeof(tag) ~= "buffer" then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (some values are invalid)`)

		key = nil
		return connectRemote(service, remote)
	end

	local requestKey = decryptAnything(ciphertext, tag, instanceArray)

	-- If the handshake fails on the server then the client has an incorrect key, so we redo the key exchange
	if not requestKey then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (server key check)\nRetrieving new key...`)

		key = nil
		return connectRemote(service, remote)
	end

	keyLocked = true

	-- We still check if the key is valid before performing a timing check, so if the key was valid it would get invalidated
	if not isValidRequestKey(requestKey) then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (key check)`)

		key = nil
		return connectRemote(service, remote)
	end

	if not EdDSA.Verify(serverPublicKey, buffer.fromstring(`{requestKey[1]}{requestKey[2]}`), keySignature) then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (key signature check)`)

		key = nil
		return connectRemote(service, remote)
	end

	-- if ping > 0 and requestTime > ping * 5 then
	-- 	return Log.warn(
	-- 		`Handshake failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping * 2}])`
	-- 	)
	-- end

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
