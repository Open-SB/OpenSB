local MLDSA87 = require("@shared/crypto/MlDSA").ML_DSA_87
local MLKEM1024 = require("@shared/crypto/MlKEM").MLKEM_1024
local CSPRNG = require("@shared/crypto/CSPRNG")
local Base64 = require("@shared/crypto/base64")

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

		local dsaPublicKey, dsaPrivateKey = MLDSA87.GenerateKeys()
		set("dsaServerPublicKey", buffer.tostring(Base64.Encode(dsaPublicKey)))
		set("dsaServerPrivateKey", buffer.tostring(Base64.Encode(dsaPrivateKey)))

		local kemPublicKey, kemPrivateKey = MLKEM1024.GenerateKeys()
		set("kemServerPublicKey", buffer.tostring(Base64.Encode(kemPublicKey)))
		set("kemServerPrivateKey", buffer.tostring(Base64.Encode(kemPrivateKey)))

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
