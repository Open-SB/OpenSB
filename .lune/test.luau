-- lune run build dev yes && rojo build ./tests.project.json --output tests.rbxlx && run-in-roblox.exe --script ./tests/runner.luau --place ./tests.rbxlx

local process = require("@lune/process")

local function ensure(result: process.SpawnResult)
	if not result.ok then
		error(`got {result.code}, stderr: {result.stderr}, stdout: {result.stdout}`, 2)
	end

	return result
end

ensure(process.spawn("lune", {
	"run",
	"build",
	"dev",
	"yes",
}))

ensure(process.spawn("rojo", { "build", "./tests.project.json", "--output", "tests.rbxlx" }))
print(ensure(process.spawn("run-in-roblox", { "--script", "./tests/pluginRun.luau", "--place", "tests.rbxlx" }, {
	stdio = "forward",
})).stdout)
