local fs = require("@lune/fs")
local process = require("@lune/process")
local stdio = require("@lune/stdio")
local serde = require("@lune/serde")

local branch = require("branch")
stdio.write(stdio.color("blue"))
print(`Building for "{branch}"`)
stdio.write(stdio.color("reset"))

if fs.isDir("build") then
	if not stdio.prompt("confirm", 'The "build" directory already exists, continuing will remove it. Is that ok?') then
		print("Cancelled build")
		return process.exit(1)
	end

	print("Removing existing build directory...")
	fs.removeDir("build")
end

print("Creating build directory...")
fs.writeDir("build")

print("Generating darklua config...")
local config = require("./config")
local generateConfig = require("./generateConfig")

local darkluaConfig = generateConfig(config)
fs.writeFile("build/.darklua.build.json", serde.encode("json", darkluaConfig, true))

print("Building...")
local result = process.spawn("darklua", {
	"process",

	"-c",
	"build/.darklua.build.json",

	"src",
	"out",
})

if not result.ok then
	stdio.write(stdio.color("red"))
	stdio.write(`Error while building:`)
	stdio.write(stdio.color("reset"))
	stdio.write(result.stderr) -- Darklua appends it's own newline

	return process.exit(result.code)
end

stdio.write(stdio.color("green"))
stdio.write("Successfully built: ")
stdio.write(stdio.color("reset"))
stdio.write(result.stdout) -- Darklua appends it's own newline

if not table.find(process.args, "keep") then
	print('Removing build directory... (pass "keep" as an argument to keep it)')
	fs.removeDir("build")
end
