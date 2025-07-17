local EdDSA = require("@shared/network/eddsa")
local Base64 = require("@shared/network/base64")
local CSPRNG = EdDSA.CSPRNG

local globalsWhichShouldBeRandomlyGenerated = table.freeze({
	"scriptHostKey",
	"localScriptHostKey",
	"moduleScriptHostKey",
})

return function(config)
	local rules = table.clone(config.darkluaRules)
	local privateKey = CSPRNG.Ed25519Random()
	local publicKey = EdDSA.PublicKey(privateKey)

	for key, value in config do
		if key == "darkluaRules" then
			continue
		end

		if table.find(globalsWhichShouldBeRandomlyGenerated, key) then
			value = CSPRNG.RandomString(256)
		elseif key == "serverPublicKey" then
			value = buffer.tostring(Base64.Encode(publicKey))
		elseif key == "serverPrivateKey" then
			value = buffer.tostring(Base64.Encode(privateKey))
		end

		table.insert(rules, 1, {
			rule = "inject_global_value",
			identifier = key,
			value = value,
		})
	end

	return {
		generator = "readable",
		bundle = {
			modules_identifier = "__DARKLUA_BUNDLE_MODULES",
			require_mode = {
				name = "path",
				sources = {
					-- Use ../ to jump out of the "build" folder
					["@client"] = "../modules/client",
					["@server"] = "../modules/server",
					["@shared"] = "../modules/shared",
				},
			},
		},

		rules = rules,
	}
end
