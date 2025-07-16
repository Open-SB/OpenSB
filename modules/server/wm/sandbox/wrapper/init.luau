local table = table
local setmetatable = setmetatable
local typeof = typeof
local rawequal = rawequal
local debug = debug
local getmetatable = getmetatable
local coroutine = coroutine
local tostring = tostring
local game = game
local type = type
local string = string
local select = select
local unpack = unpack
local error = error

local Reflection = require("./reflection")
local Protection = require("@shared/wm/protection")
local Sandbox
local wrapMap, unwrapMap

local callbackCreatorTerminatedString =
	"Script that implemented this callback has been destroyed while calling async callback"

local wrap, unwrap
local wrapMany, unwrapMany
local isWrapped, typeofWrapped

local wrappedLookup = setmetatable({}, { __mode = "v" })
local unwrappedLookup = setmetatable({}, { __mode = "k" })

-- These datatypes are completely unrelated to things we want to wrap (has no property or constructor that will take in a wrapped value)
local unwrappedDatatypes = table.freeze({
	Axes = true,
	BrickColor = true,
	CFrame = true,
	CatalogSearchParams = true,
	Color3 = true,
	ColorSequence = true,
	ColorSequenceKeypoint = true,
	DateTime = true,
	DockWidgetPluginGuiInfo = true,
	Enum = true,
	EnumItem = true,
	Enums = true,
	Faces = true,
	FloatCurveKey = true,
	Font = true,
	NumberRange = true,
	NumberSequence = true,
	NumberSequenceKeypoint = true,
	PathWaypoint = true,
	PhysicalProperties = true,
	Random = true,
	Ray = true,
	Rect = true,
	Region3 = true,
	Region3int16 = true,
	TweenInfo = true,
	UDim = true,
	UDim2 = true,
	Vector2 = true,
	Vector2int16 = true,
	Vector3 = true,
	Vector3int16 = true,
	boolean = true,
	buffer = true,
	["nil"] = true,
	number = true,
	string = true,
	thread = true,
	vector = true, -- typeof() never returns this, but adding it here anyways
})

local Module = {}
Module.UnwrappedDatatypes = unwrappedDatatypes

function Module.setSandbox(sandbox)
	if Sandbox then
		return error("Sandbox is already set.", 2)
	end

	Sandbox = sandbox
	wrapMap, unwrapMap = Sandbox.WrapMap, Sandbox.UnwrapMap
end

wrap = function(value: any, wrappedTables: table?): any
	local datatype = typeof(value)
	if unwrappedDatatypes[datatype] then
		return value
	end

	local wrappedValue = wrappedLookup[value] or wrapMap[value]
	if wrappedValue then
		return wrappedValue
	end

	-- If there's a unwrapped version of this value, then it must already be wrapped
	if unwrappedLookup[value] ~= nil then
		return value
	end

	if datatype == "table" then
		if wrappedTables then
			local wrappedTable = wrappedTables[value]
			if wrappedTable then
				return wrappedTable
			end
		else
			wrappedTables = {}
		end

		-- Tables are essentially copied, meaning any mutations to the unwrapped one will not reflect onto the wrapped one, meaning that we shouldn't link the unwrapped version of the table to this wrapped one
		-- If we want to solve this we would have to make the wrapped table into a metatable that always reads from the unwrapped one and wraps whatever it gets (and do some trickery to setmetatable, getmetatable, rawget etc to hide this)
		-- Realistically unsandboxed and sandboxed shouldn't need to communicate that often, we should however still link this wrapped version of the table back to unwrapped one

		-- If the thing we have to unwrap already has a metatable we can ingore the above

		if getmetatable(value) == nil then
			wrappedValue = {}
			wrappedTables[value] = wrappedValue

			for k, v in value do
				wrappedValue[wrap(k, wrappedTables)] = wrap(v, wrappedTables)
			end

			unwrappedLookup[wrappedValue] = value
			return wrappedValue
		end

		-- TODO: make rawset, rawget, rawlen, etc work (then make normal tables into a "metatable" to fix the above?)
		local meta = {}
		meta.__metatable = unwrap(getmetatable(value), wrappedTables)
		wrappedValue = setmetatable({}, meta)

		function meta:__index(i)
			return wrap(value[unwrap(i)])
		end
		function meta:__newindex(i, v)
			value[unwrap(i)] = unwrap(v)
		end
		function meta:__call(...)
			return wrapMany(value(unwrapMany(...)))
		end
		function meta:__concat(v)
			return wrap(value .. unwrap(v))
		end
		function meta:__iter()
			return coroutine.wrap(function(_v)
				for i, v, e in unwrap(_v) do
					coroutine.yield(wrap(i), wrap(v), wrap(e))
				end
			end),
				wrappedValue
		end
		function meta:__unm()
			return wrap(-value)
		end
		function meta:__add(v)
			return wrap(value + unwrap(v))
		end
		function meta:__sub(v)
			return wrap(value - unwrap(v))
		end
		function meta:__mul(v)
			return wrap(value * unwrap(v))
		end
		function meta:__div(v)
			return wrap(value / unwrap(v))
		end
		function meta:__mod(v)
			return wrap(value % unwrap(v))
		end
		function meta:__pow(v)
			return wrap(value ^ unwrap(v))
		end
		function meta:__tostring()
			return wrap(tostring(value))
		end
		function meta:__eq(to)
			return wrap(value == unwrap(to))
		end
		function meta:__lt(to)
			return wrap(value < unwrap(to))
		end
		function meta:__le(to)
			return wrap(value <= unwrap(to))
		end
		function meta:__len()
			return wrap(#value)
		end
	elseif datatype == "function" then
		local sandbox = Sandbox.getSandboxFromFunction(value)
		if sandbox then
			-- If the function is sandbox made, we shouldn't wrap it
			return value
		end

		local numArgs, variadic = debug.info(value, "a")
		if variadic then -- Unknown maximum number of arguments (has ...)
			wrappedValue = function(...)
				return wrapMany(value(unwrapMany(...)))
			end
		elseif numArgs > 0 then -- Known maximum number of arguments
			wrappedValue = function(...)
				local args, length = { ... }, select("#", ...)
				if numArgs < length then
					-- Clamp the amount of values to unwrap to the amount of arguments the function can take
					length = numArgs
				end

				for index = 1, length do
					args[index] = unwrap(args[index])
				end

				return wrapMany(value(unpack(args, 1, length)))
			end
		else -- No arguments
			wrappedValue = function()
				return wrapMany(value())
			end
		end

		-- Set the environment of the wrapped function to the wrapped version of the unwrapped functions environment
		setfenv(wrappedValue, wrap(getfenv(value)))
	else
		if datatype == "Instance" and Protection.isReadProtected(value) then
			return error("Attempted to access protected instance", 2)
		end

		wrappedValue = newproxy(true)

		local meta = getmetatable(wrappedValue)
		meta.__metatable = wrap(getmetatable(value), wrappedTables)
		Reflection.set(meta, Reflection[datatype])
	end

	wrappedLookup[value] = wrappedValue
	unwrappedLookup[wrappedValue] = value

	return wrappedValue
end
Module.wrap = wrap

unwrap = function(value: any, unwrappedTables: table?): any
	local datatype = typeof(value)
	if unwrappedDatatypes[datatype] then
		return value
	end

	local unwrappedValue = unwrappedLookup[value] or unwrapMap[value]
	if unwrappedValue then
		return unwrappedValue
	end

	-- If there's a wrapped version of this value, then it must already be unwrapped
	if wrappedLookup[value] ~= nil then
		return value
	end

	-- If there is no unwrapped version of this value already, then that means the value was created inside the sandbox (functions, tables, metatables)
	if datatype == "table" then
		if unwrappedTables then
			local unwrappedTable = unwrappedTables[value]
			if unwrappedTable then
				return unwrappedTable
			end
		else
			unwrappedTables = {}
		end

		-- Tables are essentially copied, meaning any mutations to the wrapped one will not reflect onto the unwrapped one, meaning that we shouldn't link the wrapped version of the table to this unwrapped one
		-- If we want to solve this we would have to make the wrapped table into a metatable that always reads from the unwrapped one and wraps whatever it gets (and do some trickery to setmetatable, getmetatable, rawget etc to hide this)
		-- Realistically unsandboxed and sandboxed shouldn't need to communicate that often, we should however still link this unwrapped version of the table back to wrapped one

		-- If the thing we have to unwrap already has a metatable we can ingore the above

		if getmetatable(value) == nil then
			unwrappedValue = {}
			unwrappedTables[value] = unwrappedValue

			for k, v in value do
				unwrappedValue[unwrap(k, unwrappedTables)] = unwrap(v, unwrappedTables)
			end

			wrappedLookup[unwrappedValue] = value
			return unwrappedValue
		end

		-- TODO: make rawset, rawget, rawlen, etc work (sandbox setmetatable and getmetatable to lookup raw table from a metatable)
		local meta = {}
		meta.__metatable = unwrap(getmetatable(value), unwrappedTables)
		unwrappedValue = setmetatable({}, meta)

		function meta:__index(i)
			return unwrap(value[wrap(i)])
		end
		function meta:__newindex(i, v)
			value[wrap(i)] = wrap(v)
		end
		function meta:__call(...)
			return unwrapMany(value(wrapMany(...)))
		end
		function meta:__concat(v)
			return unwrap(value .. wrap(v))
		end
		function meta:__iter()
			return coroutine.wrap(function(_v)
				for i, v, e in wrap(_v) do
					coroutine.yield(unwrap(i), unwrap(v), unwrap(e))
				end
			end),
				unwrappedValue
		end
		function meta:__unm()
			return unwrap(-value)
		end
		function meta:__add(v)
			return unwrap(value + wrap(v))
		end
		function meta:__sub(v)
			return unwrap(value - wrap(v))
		end
		function meta:__mul(v)
			return unwrap(value * wrap(v))
		end
		function meta:__div(v)
			return unwrap(value / wrap(v))
		end
		function meta:__mod(v)
			return unwrap(value % wrap(v))
		end
		function meta:__pow(v)
			return unwrap(value ^ wrap(v))
		end
		function meta:__tostring()
			return unwrap(tostring(value))
		end
		function meta:__eq(to)
			return unwrap(value == wrap(to))
		end
		function meta:__lt(to)
			return unwrap(value < wrap(to))
		end
		function meta:__le(to)
			return unwrap(value <= wrap(to))
		end
		function meta:__len()
			return unwrap(#value)
		end
	elseif datatype == "function" then
		local sandbox = Sandbox.getSandboxFromFunction(value)
		if not sandbox then
			-- If the function isn't sandbox made, we shouldn't unwrap it
			return value
		end

		local numArgs, variadic = debug.info(value, "a")
		if variadic then -- Unknown maximum number of arguments (has ...)
			-- This unwrapped function won't respect the amount of args that is shown by debug.info
			unwrappedValue = function(...)
				if sandbox.Terminated then
					value = nil -- Remove reference to callback (no longer relevant if the creator is terminated)
					sandbox = Sandbox.terminated -- The same applies to the actual sandbox

					return error(callbackCreatorTerminatedString, 2)
				end

				return unwrapMany(value(wrapMany(...)))
			end
		elseif numArgs > 0 then -- Known maximum number of arguments
			-- This unwrapped function won't respect the amount of args that is shown by debug.info (and will instead show as variadic)
			unwrappedValue = function(...)
				if sandbox.Terminated then
					value = nil -- Remove reference to callback (no longer relevant if the creator is terminated)
					sandbox = Sandbox.terminated -- The same applies to the actual sandbox

					return error(callbackCreatorTerminatedString, 2)
				end

				local args, length = { ... }, select("#", ...)
				if numArgs < length then
					-- Clamp the amount of values to wrap to the amount of arguments the function can take
					length = numArgs
				end

				for index = 1, length do
					args[index] = wrap(args[index])
				end

				return unwrapMany(value(unpack(args, 1, length)))
			end
		else -- No arguments
			unwrappedValue = function()
				if sandbox.Terminated then
					value = nil -- Remove reference to callback (no longer relevant if the creator is terminated)
					sandbox = Sandbox.terminated -- The same applies to the actual sandbox

					return error(callbackCreatorTerminatedString, 2)
				end

				return unwrapMany(value())
			end
		end

		-- Set the environment of the unwrapped function to the unwrapped version of the wrapped functions environment
		setfenv(unwrappedValue, unwrap(getfenv(value)))
	else
		return value
	end

	wrappedLookup[unwrappedValue] = value
	unwrappedLookup[value] = unwrappedValue

	return unwrappedValue
end
Module.unwrap = unwrap

wrapMany = function(...: any...): any...
	local values, length = { ... }, select("#", ...)
	for index = 1, length do
		values[index] = wrap(values[index])
	end

	return unpack(values, 1, length)
end
Module.wrapMany = wrapMany

unwrapMany = function(...: any...): any...
	local values, length = { ... }, select("#", ...)
	for index = 1, length do
		values[index] = unwrap(values[index])
	end

	return unpack(values, 1, length)
end
Module.unwrapMany = unwrapMany

isWrapped = function(value): boolean
	return unwrappedLookup[value] ~= nil
end
Module.isWrapped = isWrapped

typeofWrapped = function(value): string
	return typeof(unwrappedLookup[value] or value)
end
Module.typeofWrapped = typeofWrapped

return table.freeze(Module)
