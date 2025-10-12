local renv = getfenv()

local anyIssues = false
local function fail(message: string?, level: number?)
	anyIssues = true
	warn(debug.traceback(message, (level or 1) + 1))
end

local function check<T>(value: T, message: string?, level: number?): T
	if not value then
		fail(message, (level or 1) + 1)
	end

	return value
end

local function checkRuns<I..., O...>(message: string?, func: (I...) -> O..., ...: I...): (boolean, O...)
	return xpcall(func, function(message)
		fail(`Function threw an error: {message}`, 2)
	end)
end

local function checkError<T...>(message: string?, match: string, func: (T...) -> (), ...: T...)
	local success, errMessage = pcall(func, ...)
	if not check(not success, message or `Function didn't error (expected "{match}")`, 2) then
		return
	end

	check(
		string.find(errMessage, match),
		message or `Function threw an unexpected error (expected "{match}", got "{message}")`
	)
end

local function suite(name, func: () -> ())
	xpcall(func, function(message)
		fail(`Suite "{name}" threw an error: {message}`, 2)
	end)
end

local start = os.clock()

suite("Environment", function()
	local env = getfenv()
	assert(type(env) == "table", "Unable to get environment")

	local script = check(rawget(env, "script"), 'Missing script global "script"')
	local owner = check(rawget(env, "owner"), 'Missing script global "script"')
	local _G = check(rawget(env, "_G"), 'Missing script global "_G"')
	local shared = check(rawget(env, "shared"), 'Missing script global "shared"')

	check(typeof(script) == "Instance" and script:IsA("BaseScript"), [[Script global "script" isn't a BaseScript]])
	check(typeof(owner) == "Instance" and owner:IsA("Player"), [[Script global "owner" isn't a Player]])
	check(type(_G) == "table", [[Script global "_G" isn't a table]])
	check(type(shared) == "table", [[Script global "shared" isn't a table]])

	check(rawget(env, "_VERSION") == nil, "Globals are defined as script globals")

	--[[
	    Lua Global variables
	    https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#properties
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#_VERSION
	check(_VERSION == "Luau", '_VERSION ~= "Luau"')

	--[[
	    Lua Global functions
	    https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#functions
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#assert
	checkRuns(nil, function()
		assert(true, "Shouldn't error")
	end)

	checkError(nil, "1234", function()
		assert(false, "1234")
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#error
	checkError(nil, "12345", function()
		error("12345")
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#gcinfo
	suite("gcinfo", function()
		check(type(gcinfo()) == "number", "gcinfo() didn't return a number")
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#getfenv
	suite("getfenv", function()
		assert(type(getfenv()) == "table", "getfenv() didn't return a table")

		check(getfenv() == getfenv(), "getfenv() shouldn't return different objects for the same environment")
		check(
			getfenv(getfenv) == getfenv(0),
			"Calling getfenv() on protected objects should return the environment of the thread"
		)
		checkError("negative levels shouldn't be allowed in getfenv()", "level must be non%-negative", getfenv, -1)
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#getmetatable

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#ipairs

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#loadstring

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#newproxy

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#next

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#pairs

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#pcall
	suite("pcall", function()
		checkRuns("shouldn't propagate errors", function()
			pcall(function()
				error("this should be caught!")
			end)
		end)
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#print

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawequal

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawget

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawlen

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawset

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#require

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#select

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#setfenv
	suite("setfenv", function()
		checkError(
			"setfenv() shouldn't be able to set the environment of protected objects",
			"'setfenv' cannot change environment of given object",
			setfenv,
			setfenv,
			{}
		)

		checkError("negative levels shouldn't be allowed in setfenv()", "level must be non%-negative", setfenv, -1, {})

		checkError(
			"setfenv() should throw an error when the level is under 1, above -1, but not equal to 0",
			"'setfenv' cannot change environment of given object",
			setfenv,
			0.5,
			{}
		)

		checkError(
			"setfenv() should throw an error when the level is under 1, above -1, but not equal to 0",
			"'setfenv' cannot change environment of given object",
			setfenv,
			-0.5,
			{}
		)

		do
			checkRuns(nil, function()
				setfenv(0, {})

				check(getfenv(1) ~= getfenv(0), "getfenv(1) == getfenv(0) when setfenv() has changed level 0")
			end)

			setfenv(0, renv)
		end
	end)

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#setmetatable

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#tonumber

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#tostring

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#type

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#unpack

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#xpcall

	--[[
	    Roblox Global variables
	    https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#properties
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#Enum
	check(typeof(Enum) == "Enums", [[Global "Enum" isn't an Enums]])

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#game
	check(typeof(game) == "Instance", [[Global "game" isn't an Instance]])

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#workspace
	check(typeof(workspace) == "Instance", [[Global "workspace" isn't an Instance]])

	--[[
	    Roblox Global functions
	    https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#functions
    ]]
end)

local ms = math.round((os.clock() - start) * 1000 * 1000) / 1000
if anyIssues then
	print(`Some issues occured, ran in {ms}ms`)
else
	print(`All tests ran without issues in {ms}ms`)
end
