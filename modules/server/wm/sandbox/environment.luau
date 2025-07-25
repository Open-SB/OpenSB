local setmetatable = setmetatable
local error = error
local table = table
local type = type
local select = select
local typeof = typeof
local rawequal = rawequal
local setfenv = setfenv
local getfenv = getfenv
local pcall = pcall
local coroutine = coroutine
local ipairs = ipairs
local print = print
local warn = warn
local rawset = rawset
local math = math
local tonumber = tonumber
local Instance = Instance
local task = task
local debug = debug

local ManagerCommunication = require("@shared/wm/communication")
local Functions = require("@shared/functions")
local Protection = require("@shared/wm/protection")
local Errors = require("@shared/errors")

local Wrapper = require("./wrapper")
local Sandbox
local BlockedInstances = require("./blockedInstances")

local getSandbox
local assertTerminated
local claimEnvironment

local wrap, unwrap = Wrapper.wrap, Wrapper.unwrap
local wrapMany, unwrapMany = Wrapper.wrapMany, Wrapper.unwrapMany
local typeofWrapped = Wrapper.typeofWrapped

local nullTerminate = Functions.nullTerminate

local isRemoveProtected = Protection.isRemoveProtected
local isWriteProtected = Protection.isWriteProtected
local isReadProtected = Protection.isReadProtected

local renv = getfenv() -- Raw environment
local senv = {} -- Sandboxed environment
local wmap, uwmap -- Wrap map and Unwrap map

local Module = {}

function Module.setSandbox(sandbox)
	if Sandbox then
		return error("Sandbox is already set.", 2)
	end

	Sandbox = sandbox
	wmap, uwmap = Sandbox.WrapMap, Sandbox.UnwrapMap
	getSandbox = Sandbox.getSandbox
	assertTerminated = Sandbox.assertTerminated
	claimEnvironment = Sandbox.claimEnvironment
end

function Module.new(globals: table?)
	return setmetatable(wrap(globals) or {}, {
		__metatable = "The metatable is locked",
		__index = function(_, index)
			assertTerminated()
			return senv[index] or wrap(renv[index])
		end,
	})
end

local sbSource = debug.info(function() end, "s") -- Taking advantage of that everything is being bundled into one script
local function isStackSafe(stack: () -> () | number, options: { thread: thread?, allowCFunctions: boolean? }?): boolean
	options = options or {}

	local thread = options.thread or coroutine.running()
	if type(stack) == "number" and rawequal(thread, coroutine.running()) then
		-- Offset the stack by 1 to account for this function (if the stack level is in this thread)
		stack += 1
	end

	local source, line, func
	if type(stack) == "function" then
		source, line, func = debug.info(stack, "slf")
	else
		source, line, func = debug.info(thread, stack, "slf")
	end

	if not func then
		-- If the stack is invalid then it's safe
		return true
	end

	local wrappedFunc = wmap[func]
	if wrappedFunc and wrappedFunc ~= func then
		-- If this function is mapped to a wrapped version, then it can't be safe
		return false
	end

	local unwrappedFunc = uwmap[func]
	if unwrappedFunc and unwrappedFunc ~= func then
		-- If this function is mapped to an unwrapped version, then check that function instead
		source, line = debug.info(unwrappedFunc, "sl")
		func = unwrappedFunc
	end

	if source == sbSource then
		-- The the stack originates from the sb it's not safe
		return false
	end

	if source == "[C]" and line == -1 then
		-- C functions are considered "unsafe", unless specified that they are
		return options.allowCFunctions == true
	end

	-- The function is only safe if it's owned by a sandbox
	return Sandbox.getSandboxFromFunction(func) ~= nil
end

-- Level is the how many levels to seek, skip is purely for optimization (automatically skips that many levels as if they were already unsafe, defaults to 1)
local function seekSafeLevel(
	level: number?,
	options: { skip: number?, thread: thread?, allowCFunctions: boolean?, beginsAt0: boolean? }?
): number
	options = options or {}
	level = math.floor(level or 1)

	local returnTopLevel = level == 0 and not options.beginsAt0
	local thread = options.thread or coroutine.running()
	local safeLevels: { number } = {}

	local offset = if rawequal(thread, coroutine.running()) then 1 else 0
	local unsafeAmount = (options.skip or offset) + offset -- Amount of unsafe levels at the top (offset this function, and if not set, function above this)
	local currentLevel = unsafeAmount
	local size = if options.beginsAt0 then 0 else 1
	while debug.info(thread, currentLevel, "f") ~= nil do
		if isStackSafe(currentLevel, { thread = thread, allowCFunctions = options.allowCFunctions }) then
			safeLevels[size] = currentLevel - 1
			size += 1
			unsafeAmount = 0

			if not returnTopLevel and size >= (level + 1) then
				break
			end
		else
			unsafeAmount += 1
		end

		currentLevel += 1
	end

	if returnTopLevel then
		-- Return the highest level found
		return safeLevels[#safeLevels]
	end

	if level > #safeLevels then
		-- If the level is higher than the amount of safe levels, then add the missing amount of levels (plus the amount of unsafe to offset them)
		local missing = (safeLevels[#safeLevels] or 0) - #safeLevels
		return missing + level + unsafeAmount
	end

	return safeLevels[level]
end

local function missingArg(functionName: string, index: number, message: string, levelOffset: number?)
	return error(
		"missing argument #" .. index .. " to '" .. functionName .. "' (" .. message .. ")",
		seekSafeLevel(1, { skip = (levelOffset or 1) + 1 }) or 0
	)
end

local function invalidArg(functionName: string, index: number, message: string, levelOffset: number?)
	return error(
		"invalid argument #" .. index .. " to '" .. functionName .. "' (" .. message .. ")",
		seekSafeLevel(1, { skip = (levelOffset or 1) + 1 }) or 0
	)
end

local function assertArg(functionName: string, index: number, condition: boolean, message: string, levelOffset: number?)
	if condition == false then
		invalidArg(functionName, index, message, (levelOffset or 1) + 1)
	end
end

local function getArg(index: number, ...): any
	return (select(index, ...)) -- Wrapped in () to only return 1 value
end

local function checkArg(functionName: string, expected: { string } | string, index: number, ...): any
	local nargs = select("#", ...)
	if type(expected) == "table" then
		if nargs < index then
			return missingArg(functionName, index, expected[1] .. " expected", 2)
		end

		local arg = getArg(index, ...)
		local argType = typeofWrapped(arg)
		if not table.find(expected, argType) then
			return invalidArg(functionName, index, expected[1] .. " expected, got " .. argType, 2)
		end

		return arg
	end

	if nargs < index then
		return missingArg(functionName, index, expected .. " expected", 2)
	end

	local arg = getArg(index, ...)
	local argType = typeofWrapped(arg)
	if argType ~= expected then
		return invalidArg(functionName, index, expected .. " expected, got " .. argType, 2)
	end

	return arg
end

local function checkOptionalArg(functionName: string, expected: { string } | string, index: number, ...): any
	local arg = getArg(index, ...)
	if rawequal(arg, nil) then
		return arg
	end

	return checkArg(functionName, expected, index, ...)
end

local function replaceLibrary(library: table, mutator: (table) -> never): table
	local lib = table.clone(library)
	mutator(lib, library)

	return table.freeze(lib)
end

local function manyToString(...): string
	local length = select("#", ...)
	local input, output = { ... }, table.create(length)

	for index = 1, length do
		local value = input[index]
		output[index] = if value == nil then "nil" else tostring(value)
	end

	return table.concat(output, " ")
end

-- We package args inside bindable functions when transmitting them via ManagerCommunication
-- This prevents roblox from replacing functions that are being sent over with ones that errors with "Attempt to load a function from a different Lua VM"
-- (Because we only read from the bindable when it has been sent back to this WorkerManager)
local function package(...)
	local packed = table.pack(...)
	local bindable = Instance.new("BindableFunction")
	bindable.OnInvoke = function()
		-- Single use
		bindable.OnInvoke = function() end
		bindable:Destroy()

		return unpack(packed, 1, packed.n)
	end

	return bindable
end

-- Anything such as "senv.x = renv.x" is purely for optimization, to skip any potential wrapping of the global.
-- This kind of optimization doesn't really need to be added for deprecated things.
function Module:Init()
	do
		local function map(unwrapped, wrapped)
			if not unwrapped or Wrapper.UnwrappedDatatypes[typeof(unwrapped)] then
				return
			end

			wmap[unwrapped] = wrapped
			if type(unwrapped) == "table" and type(wrapped) == "table" then
				for k, v in wrapped do
					map(unwrapped[k], v)
				end
			end
		end

		setmetatable(senv, {
			__newindex = function(_, index, value)
				rawset(senv, index, value)
				map(renv[index], value)
			end,
		})
	end

	--[[
	    Lua Global variables
	    https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#properties
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#_VERSION
	senv._VERSION = renv._VERSION

	--[[
	    Lua Global functions
	    https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#functions
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#assert
	senv.assert = renv.assert

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#collectgarbage
	senv.collectgarbage = renv.collectgarbage

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#error
	senv.error = function(...)
		local level = checkOptionalArg("error", "number", 2, ...)
		local message = ...
		if rawequal(message, nil) then
			return error("Error occurred, no output from Lua.", 0)
		end

		message = tostring(unwrap(message))
		level = math.floor(level or 1)

		if level < 1 then
			return error(message, 0)
		end

		local safeLevel = seekSafeLevel(level or 1)
		return error(message, safeLevel or 0)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#getfenv
	senv.getfenv = function(...)
		local stack = ...

		local stackType = type(stack)
		if stackType == "number" then
			assertArg("getfenv", 1, stack >= 0, "level must be non-negative", 1)
			stack = seekSafeLevel(stack)
		elseif stackType == "function" then
			if not isStackSafe(stack) then
				stack = seekSafeLevel()
			end
		elseif stackType == "nil" then
			stack = seekSafeLevel()
		else
			return invalidArg("getfenv", 1, "number expected, got " .. typeof(stack), 1)
		end

		if type(stack) == "number" and not debug.info(stack, "f") then
			return invalidArg("getfenv", 1, "invalid level", 1)
		end

		local fenv = getfenv(unwrap(stack))
		return if Sandbox.getSandboxFromEnvironment(fenv) then fenv else wrap(fenv)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#getmetatable
	senv.getmetatable = renv.getmetatable

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#ipairs
	senv.ipairs = renv.ipairs

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#loadstring
	senv.loadstring = renv.loadstring

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#newproxy
	senv.newproxy = renv.newproxy

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#next
	senv.next = renv.next

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#pairs
	senv.pairs = renv.pairs

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#pcall
	senv.pcall = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		return (function(_sandbox, ...)
			assertTerminated(_sandbox)
			return ...
		end)(sandbox, pcall(...))
	end
	senv.ypcall = senv.pcall

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#print
	senv.print = function(...)
		(function(...)
			ManagerCommunication:Send("log", getSandbox().Owner, manyToString(...))

			-- Fire LogService events
			print(...)
		end)(unwrapMany(...))
	end

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawequal
	senv.rawequal = renv.rawequal

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawget
	senv.rawget = renv.rawget

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawlen
	senv.rawlen = renv.rawlen

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#rawset
	senv.rawset = renv.rawset

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#select
	senv.select = renv.select

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#setfenv
	senv.setfenv = function(...)
		local env = checkArg("setfenv", "table", 2, ...)
		local stack = ...

		local stackType = type(stack)
		if stackType == "number" then
			assertArg("setfenv", 1, stack >= 0, "level must be non-negative")
			if stack == 0 then
				-- setfenv does nothing when stack is set to 0
				return
			end

			if math.floor(stack) < 1 then
				-- When stack is under 1 (e.g 0.7) setfenv throws this error
				return error("'setfenv' cannot change environment of given object", seekSafeLevel())
			end

			stack = seekSafeLevel(stack)
		elseif stackType == "function" then
			if not isStackSafe(stack) then
				return error("'setfenv' cannot change environment of given object", seekSafeLevel())
			end
		elseif stackType == "nil" then
			stack = seekSafeLevel()
		else
			return invalidArg("getfenv", 1, "number expected, got " .. typeof(stack), 1)
		end

		if type(stack) == "number" and not debug.info(stack, "f") then
			return invalidArg("getfenv", 1, "invalid level", 1)
		end

		claimEnvironment(env)
		return setfenv(stack, env)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#setmetatable
	senv.setmetatable = renv.setmetatable

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#tonumber
	senv.tonumber = renv.tonumber

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#tostring
	senv.tostring = function(...)
		if select("#", ...) < 1 then
			return error("missing argument #1", seekSafeLevel())
		end

		return tostring(unwrap((...)))
	end

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#unpack
	senv.unpack = renv.unpack

	-- https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#xpcall
	senv.xpcall = function(...)
		local errorHandler = checkArg("xpcall", "function", 2, ...)
		local func = ...

		local sandbox = getSandbox()
		assertTerminated(sandbox)

		return (function(_sandbox, _errorHandler, success, message, ...)
			assertTerminated(_sandbox)
			if success then
				return true, message, ...
			end

			local errorHandlerSuccess, result = pcall(_errorHandler, message)
			assertTerminated(_sandbox)

			return false, if errorHandlerSuccess then result else "error in error handling"
		end)(sandbox, errorHandler, pcall(func, select(3, ...)))
	end

	--[[
	    Roblox Global variables
	    https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#properties
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#Enum
	senv.Enum = renv.Enum

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#game
	senv.game = wrap(renv.game)

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#workspace
	senv.workspace = wrap(renv.workspace)

	--[[
	    Roblox Global functions
	    https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#functions
    ]]

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#delay
	senv.delay = function(...)
		if select("#", ...) < 2 then
			return error("delay function requires 2 arguments", seekSafeLevel())
		end

		local sandbox = getSandbox()
		assertTerminated(sandbox)

		sandbox.Threads[task.spawn(function(_sandbox, delayTime, callback)
			local delta, total = renv.wait(delayTime)
			assertTerminated(_sandbox)
			callback(delta, total)
		end, sandbox, ...)] =
			true

		return
	end

	-- delay == Delay is false
	senv.Delay = function(...)
		return senv.delay(...)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#gcinfo
	senv.gcinfo = renv.gcinfo

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#printidentity
	senv.printidentity = function(...)
		local sandbox = getSandbox()
		local length = select("#", ...)

		-- This will always print that the current identity is 2 in the SB console (you shouldn't really be able to escalate permissions in the first place)
		if length > 0 then
			local last = ({ ... })[length]
			if type(last) == "string" or type(last) == "number" then
				ManagerCommunication:Send("log", sandbox.Owner, last .. " 2")
			else
				ManagerCommunication:Send("log", sandbox.Owner, "(null) 2")
			end
		else
			ManagerCommunication:Send("log", sandbox.Owner, "Current identity is 2")
		end

		-- Fire LogService events
		renv.printidentity(...)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#require
	senv.require = function(...)
		local target = ...
		if typeof(target) ~= "Instance" and type(target) ~= "string" then
			target = Functions.toCDouble(target) or target
		end

		if type(target) == "number" then
			return error(Errors.cannotAssetRequire(), 0)
		end

		return wrapMany(renv.require(unwrap(target)))
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#settings
	senv.settings = renv.settings

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#spawn
	senv.spawn = function(...)
		if select("#", ...) < 1 then
			return error("Spawn function requires 1 argument", seekSafeLevel())
		end

		local sandbox = getSandbox()
		assertTerminated(sandbox)

		sandbox.Threads[task.spawn(function(_sandbox, callback)
			local delta, total = renv.wait()
			assertTerminated(_sandbox)
			callback(delta, total)
		end, sandbox, ...)] =
			true

		return
	end

	-- spawn == Spawn is false
	senv.Spawn = function(...)
		return senv.spawn(...)
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#tick
	senv.tick = renv.tick

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#time
	senv.time = renv.time

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#version
	senv.version = renv.version

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#typeof
	senv.typeof = function(...)
		if select("#", ...) < 1 then
			return error("missing argument #1", seekSafeLevel())
		end

		return typeofWrapped((...))
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#wait
	senv.wait = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		local delta, total = renv.wait(...)
		assertTerminated(sandbox)

		return delta, total
	end

	-- https://create.roblox.com/docs/reference/engine/globals/RobloxGlobals#warn
	senv.warn = function(...)
		(function(...)
			ManagerCommunication:Send("warn", getSandbox().Owner, manyToString(...))

			-- Fire LogService events
			warn(...)
		end)(unwrapMany(...))
	end

	--[[
	    Libraries
		https://create.roblox.com/docs/reference/engine/libraries
    ]]

	-- https://create.roblox.com/docs/reference/engine/libraries/bit32
	senv.bit32 = renv.bit32

	-- https://create.roblox.com/docs/reference/engine/libraries/buffer
	senv.buffer = renv.buffer

	-- https://create.roblox.com/docs/reference/engine/libraries/coroutine
	senv.coroutine = replaceLibrary(renv.coroutine, function(l, rl)
		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#close
		l.close = function(...)
			-- Just a lazy way to not having to do our own typechecking to avoid unnecessary work
			return (function(thread, ...)
				getSandbox().Threads[thread] = nil

				return ...
			end)((...), coroutine.close(...))
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#create
		l.create = function(...)
			local thread = coroutine.create(...)
			getSandbox().Threads[thread] = true

			return thread
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#isyieldable
		l.isyieldable = rl.isyieldable

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#resume
		l.resume = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local thread = checkArg("resume", "thread", 1, ...)
			sandbox.Threads[thread] = true

			return coroutine.resume(thread, select(2, ...))
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#running
		l.running = rl.running

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#status
		l.status = rl.status

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#wrap
		l.wrap = function(...)
			local func = checkArg("wrap", "function", 1, ...)
			local thread = coroutine.create(func)
			getSandbox().Threads[thread] = true

			return function(...)
				local sandbox = getSandbox()
				assertTerminated(sandbox)

				if coroutine.status(thread) == "dead" then
					sandbox.Threads[thread] = nil

					return error("cannot resume dead coroutine", seekSafeLevel())
				end

				sandbox.Threads[thread] = true

				local resumeSuccess, resumeResult = coroutine.resume(thread, ...)
				if not resumeSuccess then
					return error(resumeResult, 2)
				end

				return resumeResult
			end
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/coroutine#yield
		l.yield = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			return (function(_sandbox, ...)
				assertTerminated(_sandbox)
				return ...
			end)(sandbox, coroutine.yield(...))
		end
	end)

	-- https://create.roblox.com/docs/reference/engine/libraries/debug
	senv.debug = replaceLibrary(renv.debug, function(r, rl)
		-- https://create.roblox.com/docs/reference/engine/libraries/debug#traceback
		r.traceback = function(...)
			local message = checkOptionalArg("traceback", { "string", "number" }, 1, ...) -- Numbers can be cast into strings
			local level = checkOptionalArg("traceback", { "number", "string" }, 2, ...) -- Strings can be cast into numbers

			if message and type(message) == "number" then
				-- Cast number into string
				message = tostring(message)
			end

			if level and type(level) == "string" then
				-- Cast string into number
				level = tonumber(level)
				if not level then
					return invalidArg("traceback", 2, "number expected, got string", 1)
				end
			end
			level = (level or 1) + 1 -- Offset to account for this function

			local traces = { message }
			while true do
				local func = debug.info(level, "f")
				if not func then
					break
				end

				if isStackSafe(func) then
					local source, line, name = debug.info(func, "sln")
					if name and #name > 0 then
						table.insert(traces, `{source}:{line} function {name}`)
					else
						table.insert(traces, `{source}:{line}`)
					end
				end

				level += 1
			end

			return table.concat(traces, "\n") .. "\n"
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#info
		r.info = function(...)
			local stack = ...
			local optionsIndex = 2

			local stackType = type(stack)
			if stackType == "thread" then
				local level = checkArg("info", "number", 2, ...)
				assertArg("info", 2, level >= 0, "level can't be negative")

				optionsIndex = 3
				stack = debug.info(
					stack,
					seekSafeLevel(level, {
						thread = stack,
						allowCFunctions = true,
						beginsAt0 = true,
					}),
					"f"
				)

				if not stack then
					return
				end
			elseif stackType == "number" then
				assertArg("info", 1, stack >= 0, "level can't be negative")

				stack = debug.info(
					seekSafeLevel(stack, {
						allowCFunctions = true,
						beginsAt0 = true,
					}),
					"f"
				)

				if not stack then
					return
				end
			elseif stackType ~= "function" then
				return invalidArg("info", 1, "function or level expected")
			end

			local options = checkArg("info", { "string", "number" }, optionsIndex, ...) -- Numbers are cast into strings
			return wrapMany(debug.info(uwmap[stack] or stack, options))
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#profilebegin
		r.profilebegin = rl.profilebegin

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#profileend
		r.profileend = rl.profileend

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#getmemorycategory
		r.getmemorycategory = rl.getmemorycategory

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#setmemorycategory
		r.setmemorycategory = rl.setmemorycategory

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#resetmemorycategory
		r.resetmemorycategory = rl.resetmemorycategory

		-- https://create.roblox.com/docs/reference/engine/libraries/debug#dumpcodesize
		r.dumpcodesize = rl.dumpcodesize
	end)

	-- https://create.roblox.com/docs/reference/engine/libraries/math
	senv.math = renv.math

	-- https://create.roblox.com/docs/reference/engine/libraries/os
	senv.os = renv.os

	-- https://create.roblox.com/docs/reference/engine/libraries/string
	senv.string = renv.string
	-- This library should never be sandboxed, if it ever has to for some reason we will have to use a Lua VM instead of loadstring
	-- (strings have their __index metamethod set to the string library, and could be bypassed by using that)

	-- https://create.roblox.com/docs/reference/engine/libraries/table
	senv.table = renv.table

	-- https://create.roblox.com/docs/reference/engine/libraries/task
	senv.task = replaceLibrary(renv.task, function(l, rl)
		-- https://create.roblox.com/docs/reference/engine/libraries/task#spawn
		l.spawn = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local thread = task.spawn(...)
			sandbox.Threads[thread] = true

			return thread
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/task#defer
		l.defer = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local thread = task.defer(...)
			sandbox.Threads[thread] = true

			return thread
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/task#delay
		l.delay = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local thread = task.delay(...)
			sandbox.Threads[thread] = true

			return thread
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/task#desynchronize
		l.desynchronize = rl.desynchronize

		-- https://create.roblox.com/docs/reference/engine/libraries/task#synchronize
		l.synchronize = rl.synchronize

		-- https://create.roblox.com/docs/reference/engine/libraries/task#wait
		l.wait = function(...)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local delta = task.wait(...)
			assertTerminated(sandbox)

			return delta
		end

		-- https://create.roblox.com/docs/reference/engine/libraries/task#cancel
		l.cancel = function(...)
			task.cancel(...)
			getSandbox().Threads[(...)] = nil
		end
	end)

	-- https://create.roblox.com/docs/reference/engine/libraries/utf8
	senv.utf8 = renv.utf8

	-- https://create.roblox.com/docs/en-us/reference/engine/libraries/vector
	senv.vector = renv.vector

	--[[
	    Datatypes
		https://create.roblox.com/docs/reference/engine/datatypes
    ]]

	-- https://create.roblox.com/docs/reference/engine/datatypes/Axes
	senv.Axes = renv.Axes

	-- https://create.roblox.com/docs/reference/engine/datatypes/BrickColor
	senv.BrickColor = renv.BrickColor

	-- https://create.roblox.com/docs/reference/engine/datatypes/CatalogSearchParams
	senv.CatalogSearchParams = renv.CatalogSearchParams

	-- https://create.roblox.com/docs/reference/engine/datatypes/CFrame
	senv.CFrame = renv.CFrame

	-- https://create.roblox.com/docs/reference/engine/datatypes/Color3
	senv.Color3 = renv.Color3

	-- https://create.roblox.com/docs/reference/engine/datatypes/ColorSequence#new
	senv.ColorSequence = renv.ColorSequence

	-- https://create.roblox.com/docs/reference/engine/datatypes/ColorSequenceKeypoint
	senv.ColorSequenceKeypoint = renv.ColorSequenceKeypoint

	-- https://create.roblox.com/docs/reference/engine/datatypes/DateTime
	senv.DateTime = renv.DateTime

	-- https://create.roblox.com/docs/reference/engine/datatypes/DockWidgetPluginGuiInfo
	senv.DockWidgetPluginGuiInfo = renv.DockWidgetPluginGuiInfo

	-- https://create.roblox.com/docs/reference/engine/datatypes/Faces
	senv.Faces = renv.Faces

	-- https://create.roblox.com/docs/reference/engine/datatypes/FloatCurveKey
	senv.FloatCurveKey = renv.FloatCurveKey

	-- https://create.roblox.com/docs/reference/engine/datatypes/Font
	senv.Font = renv.Font

	-- https://create.roblox.com/docs/reference/engine/datatypes/Instance
	senv.Instance = replaceLibrary(renv.Instance, function(r, rl)
		local new = rl.new
		local fromExisting = rl.fromExisting

		-- https://create.roblox.com/docs/reference/engine/datatypes/Instance#new
		r.new = function(...)
			local className = nullTerminate(checkArg("new", "string", 1, ...))
			local parent = unwrap(checkOptionalArg("new", "Instance", 2, ...))

			if BlockedInstances[className] then
				return error(Errors.createBlockedClass(className), 0) -- Roblox seems to be throwing Instance.new errors at level 0
			end

			if parent and isWriteProtected(parent) then
				return error(Errors.parentToWriteProtected(parent), 0)
			end

			return wrap(new(className, parent))
		end

		-- https://create.roblox.com/docs/reference/engine/datatypes/Instance#fromExisting
		r.fromExisting = function(...)
			local existingInstance = unwrap(checkArg("fromExisting", "Instance", 1, ...))

			if
				typeof(existingInstance) == "Instance"
				and (BlockedInstances[existingInstance.ClassName] or isReadProtected(existingInstance))
			then
				return error(Errors.createBlockedClass(existingInstance.ClassName), 0) -- Roblox seems to be throwing Instance.fromExisting errors at level 0
			end

			return wrap(fromExisting(existingInstance))
		end
	end)

	-- https://create.roblox.com/docs/reference/engine/datatypes/NumberRange
	senv.NumberRange = renv.NumberRange

	-- https://create.roblox.com/docs/reference/engine/datatypes/NumberSequence
	senv.NumberSequence = renv.NumberSequence

	-- https://create.roblox.com/docs/reference/engine/datatypes/NumberSequenceKeypoint
	senv.NumberSequenceKeypoint = renv.NumberSequenceKeypoint

	-- https://create.roblox.com/docs/reference/engine/datatypes/PathWaypoint
	senv.PathWaypoint = renv.PathWaypoint

	-- https://create.roblox.com/docs/reference/engine/datatypes/PhysicalProperties
	senv.PhysicalProperties = renv.PhysicalProperties

	-- https://create.roblox.com/docs/reference/engine/datatypes/Random
	senv.Random = renv.Random

	-- https://create.roblox.com/docs/reference/engine/datatypes/Ray
	senv.Ray = renv.Ray

	-- https://create.roblox.com/docs/reference/engine/datatypes/Rect
	senv.Rect = renv.Rect

	-- https://create.roblox.com/docs/reference/engine/datatypes/Region3
	senv.Region3 = renv.Region3

	-- https://create.roblox.com/docs/reference/engine/datatypes/Region3int16
	senv.Region3int16 = renv.Region3int16

	-- https://create.roblox.com/docs/reference/engine/datatypes/TweenInfo
	senv.TweenInfo = renv.TweenInfo

	-- https://create.roblox.com/docs/reference/engine/datatypes/UDim
	senv.UDim = renv.UDim

	-- https://create.roblox.com/docs/reference/engine/datatypes/UDim2
	senv.UDim2 = renv.UDim2

	-- https://create.roblox.com/docs/reference/engine/datatypes/Vector2
	senv.Vector2 = renv.Vector2

	-- https://create.roblox.com/docs/reference/engine/datatypes/Vector2int16
	senv.Vector2int16 = renv.Vector2int16

	-- https://create.roblox.com/docs/reference/engine/datatypes/Vector3
	senv.Vector3 = renv.Vector3

	-- https://create.roblox.com/docs/reference/engine/datatypes/Vector3int16
	senv.Vector3int16 = renv.Vector3int16

	--[[
	    Custom global variables
    --]]

	--[[
	    Custom global functions
    --]]

	senv.NewScript = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		local source = checkArg("NewScript", "string", 1, ...)
		local parent = unwrap(checkOptionalArg("NewScript", "Instance", 2, ...))

		if not parent and select("#", ...) < 2 then -- No parent specified and "nil" wasn't passed
			parent = renv.workspace
		elseif parent then
			-- Check if the parent is RobloxLocked
			assertArg(
				"NewScript",
				2,
				pcall(function()
					local _ = parent.Name
				end),
				"instance is RobloxLocked",
				1
			)

			assertArg("NewScript", 2, not isWriteProtected(parent), "instance is write protected", 1)
		end

		local script =
			ManagerCommunication:Invoke("newScript", sandbox.Owner, source, package(unwrapMany(select(3, ...))))
		script.Parent = parent

		return wrap(script)
	end
	senv.NS = senv.NewScript

	senv.NewLocalScript = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		local source = checkArg("NewLocalScript", "string", 1, ...)
		local parent = unwrap(checkOptionalArg("NewLocalScript", "Instance", 2, ...))

		if not parent and select("#", ...) < 2 then -- No parent specified and "nil" wasn't passed
			parent = sandbox.Owner:FindFirstChildOfClass("PlayerGui")
		elseif parent then
			-- Check if the parent is RobloxLocked
			assertArg(
				"NewLocalScript",
				2,
				pcall(function()
					local _ = parent.Name
				end),
				"instance is RobloxLocked",
				1
			)

			assertArg("NewLocalScript", 2, not isWriteProtected(parent), "instance is write protected", 1)
		end

		local script =
			ManagerCommunication:Invoke("newLocalScript", sandbox.Owner, source, package(unwrapMany(select(3, ...))))
		script.Parent = parent

		return wrap(script)
	end
	senv.NLS = senv.NewLocalScript

	senv.NewModuleScript = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		local source = checkArg("NewModuleScript", "string", 1, ...)
		local parent = unwrap(checkOptionalArg("NewModuleScript", "Instance", 2, ...))

		if parent then
			-- Check if the parent is RobloxLocked
			assertArg(
				"NewModuleScript",
				2,
				pcall(function()
					local _ = parent.Name
				end),
				"instance is RobloxLocked",
				1
			)

			assertArg("NewModuleScript", 2, not isWriteProtected(parent), "instance is write protected")
		end

		local script =
			ManagerCommunication:Invoke("newModuleScript", sandbox.Owner, source, package(unwrapMany(select(3, ...))))
		script.Parent = parent

		return wrap(script)
	end
	senv.NMS = senv.NewModuleScript

	senv.NewWorker = function(...)
		local sandbox = getSandbox()
		assertTerminated(sandbox)

		local source = checkArg("NewWorker", "string", 1, ...)
		local name = checkOptionalArg("NewWorker", "string", 2, ...)

		-- Don't send the arguments with package(), as instead of playing roulette to guess if the arguments will be transformed or not (if the workerManager being used ends up being this one).
		-- We just never package it in the first place guaranteeing that the arguments are always transformed (to not cause inconsistent behaviour / confusion).
		ManagerCommunication:Send(
			"newWorker",
			sandbox.Owner,
			source,
			name or "Worker",
			table.pack(unwrapMany(select(3, ...)))
		)
	end
	senv.NW = senv.NewWorker

	setmetatable(senv, nil)
	table.freeze(senv)
end

return Module
