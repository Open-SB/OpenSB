local eddsa = require("../modules/shared/network/eddsa")
local base64 = require("../modules/shared/network/base64")

local serverPrivate = eddsa.CSPRNG.RandomBytes(32)
local serverPublic = eddsa.PublicKey(serverPrivate)

print("got public key:", buffer.tostring(base64.Encode(serverPublic)))
print("got private key:", buffer.tostring(base64.Encode(serverPrivate)))
