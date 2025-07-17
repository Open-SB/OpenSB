local EdDSA = require("@shared/network/eddsa")
local Base64 = require("@shared/network/base64")
local CSPRNG = EdDSA.CSPRNG

return function(config)
	local rules = table.clone(config.darkluaRules)

	local inject = table.clone(config)
	inject.darkluaRules = nil

	do
		local function set(global: string, value: any)
			if inject[global] ~= true then
				return
			end

			inject[global] = value
		end

		local privateKey = CSPRNG.Ed25519Random()
		local publicKey = EdDSA.PublicKey(privateKey)
		set("serverPrivateKey", buffer.tostring(Base64.Encode(privateKey)))
		set("serverPublicKey", buffer.tostring(Base64.Encode(publicKey)))

		for _, global in ipairs({ "scriptHostKey", "localScriptHostKey", "moduleScriptHostKey" }) do
			set(global, CSPRNG.RandomString(256))
		end
	end

	for key, value in inject do
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
