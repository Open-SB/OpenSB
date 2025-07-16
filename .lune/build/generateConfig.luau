return function(config)
	local rules = table.clone(config.darkluaRules)
	for k, v in config do
		if k == "darkluaRules" then
			continue
		end

		table.insert(rules, 1, {
			rule = "inject_global_value",
			identifier = k,
			value = v,
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
