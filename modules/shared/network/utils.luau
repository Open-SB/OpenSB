--!strict

local Module = {}

-- as per fips 203 & 204
Module.ML_KEM_1024_PUBLIC_KEY_SIZE = 1568
Module.ML_KEM_1024_CIPHERTEXT_SIZE = 1568

local RunService = game:GetService("RunService")
local Blake3 = require("@shared/crypto/blake3")

local allStaticFactors = (if RunService:IsStudio() then "00000000-0000-0000-0000-000000000000" else game.JobId)
	.. game.CreatorType.Name
	.. tostring(game.CreatorId)
	.. tostring(game.GameId)
	.. tostring(game.PlaceId)
	.. tostring(game.PlaceVersion)

-- context size limit is 255
local sharedStaticFactorsHash = Blake3.Digest(buffer.fromstring(allStaticFactors), 64)
local base = `opensb@networking->{buffer.tostring(sharedStaticFactorsHash)}->`

Module.getDsaContext = function(player: Player)
	return buffer.fromstring(`{base}{player.UserId}`)
end

return table.freeze(Module)
