--!strict

local Module = {}

-- as per fips 203 & 204
Module.ML_KEM_1024_PUBLIC_KEY_SIZE = 1568
Module.ML_KEM_1024_CIPHERTEXT_SIZE = 1568

local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")

local Blake3 = require("@shared/crypto/blake3")
local AEAD = require("@shared/crypto/AEAD")
local Encoding = require("@shared/network/encoding")

local allStaticFactors = (if RunService:IsStudio() then "00000000-0000-0000-0000-000000000000" else game.JobId)
	.. game.CreatorType.Name
	.. tostring(game.CreatorId)
	.. tostring(game.GameId)
	.. tostring(game.PlaceId)
	.. tostring(game.PlaceVersion)

-- context size limit is 255
local sharedStaticFactorsHash = Blake3.Digest(buffer.fromstring(allStaticFactors), 64)
local base = `opensb@networking->{buffer.tostring(sharedStaticFactorsHash)}->`

function Module.getDsaContext(player: Player)
	return buffer.fromstring(`{base}{player.UserId}`)
end

function Module.generateEntropy(): buffer
	local seed = ""
	for _ = 1, 128 do
		seed ..= HttpService:GenerateGUID(false)
	end

	return buffer.fromstring(seed)
end

-- encrypting / decrypting
export type networkData = {
	staticKey: buffer,

	nonce: number, -- Last used nonce, next nonce to use should be this + 1
	lastNonce: number, -- Last nonce sent, new nonces should always be greater than this one
}

local function padNonce(nonce: number): buffer
	local buf = buffer.create(12)
	buffer.writeu32(buf, 0, nonce)

	return buf
end

local function encryptBuffer(networkData: networkData, data: buffer): (buffer, number, buffer)
	networkData.nonce += 1
	local nonce = networkData.nonce

	local ciphertext, tag = AEAD.Encrypt(data, networkData.staticKey, padNonce(nonce))
	return ciphertext, nonce, tag
end

function Module.encryptAnything(networkData: networkData, data: any): (buffer, number, buffer, { Instance })
	local encodedData, instancesArray = Encoding.encode(data)
	local ciphertext, nonce, tag = encryptBuffer(networkData, encodedData)

	return ciphertext, nonce, tag, instancesArray
end

local function decryptBuffer(networkData: networkData, ciphertext: buffer, nonce: number, tag: buffer): buffer
	return assert(
		AEAD.Decrypt(ciphertext, networkData.staticKey, padNonce(nonce), tag),
		"failed decrypting data with aead"
	)
end

local function decryptAnything(
	networkData: networkData,
	ciphertext: buffer,
	nonce: number,
	tag: buffer,
	instanceArray: { Instance }
): any
	return Encoding.decode(decryptBuffer(networkData, ciphertext, nonce, tag), instanceArray)
end

function Module.decryptAnythingAndVerify(networkData: networkData, ciphertext, nonce, tag, instanceArray): any?
	if
		type(ciphertext) ~= "buffer"
		or type(nonce) ~= "number"
		or type(tag) ~= "buffer"
		or type(instanceArray) ~= "table"
	then
		return nil
	end

	if nonce <= networkData.lastNonce then
		-- This is a replayed nonce
		return nil
	end

	local data = decryptAnything(networkData, ciphertext, nonce, tag, instanceArray :: { Instance })
	networkData.lastNonce = nonce

	return data
end

return table.freeze(Module)
