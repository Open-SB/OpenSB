local fs = require("@lune/fs")
local serde = require("@lune/serde")
local process = require("@lune/process")

local branch = require("./branch")
local defaultConfig = serde.decode("toml", fs.readFile(".lune/build/config/default.toml")) -- ./default.toml would've been nice :sob:

local config = { branch = branch }
local function writeToConfig(dictionary: { [string]: any }?)
	for k, v in dictionary or {} do
		config[k] = v
	end
end

writeToConfig(defaultConfig.global)
writeToConfig(defaultConfig[branch])

for k, v in process.env do
	-- Filter out any env variable not present in the default config
	if config[k] == nil then
		continue
	end

	config[k] = v
end

if fs.isFile(".config.toml") then
	local customConfig = serde.decode("toml", fs.readFile(".config.toml"))
	writeToConfig(customConfig.global)
	writeToConfig(customConfig[branch])
end

for _, v in ipairs(require("./branches")) do
	config[v] = config.branch == v
end

return config
