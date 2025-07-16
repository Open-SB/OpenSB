local table = table
local setmetatable = setmetatable
local error = error
local coroutine = coroutine
local typeof = typeof
local type = type

local Wrapper
local Rules
local Functions = require("shared/functions")
local Protection = require("shared/wm/protection")

local wrap, unwrap
local wrapMany, unwrapMany

local Module = {}

function Module.set(meta, reflection)
	for k, v in reflection do
		meta[k] = v
	end
end

local default = {}
function default:__index(index)
	return wrap(unwrap(self)[unwrap(index)])
end
function default:__newindex(index, value)
	unwrap(self)[unwrap(index)] = unwrap(value)
end
function default:__call(...)
	return wrapMany(unwrap(self)(unwrapMany(...)))
end
function default:__concat(value)
	return wrap(unwrap(self) .. unwrap(value))
end
function default:__iter()
	return coroutine.wrap(function(_self)
		for index, value, extra in unwrap(_self) do
			coroutine.yield(wrap(index), wrap(value), wrap(extra))
		end
	end),
		self
end
function default:__unm()
	return wrap(-unwrap(self))
end
function default:__add(value)
	return wrap(unwrap(self) + unwrap(value))
end
function default:__sub(value)
	return wrap(unwrap(self) - unwrap(value))
end
function default:__mul(value)
	return wrap(unwrap(self) * unwrap(value))
end
function default:__div(value)
	return wrap(unwrap(self) / unwrap(value))
end
function default:__mod(value)
	return wrap(unwrap(self) % unwrap(value))
end
function default:__pow(value)
	return wrap(unwrap(self) ^ unwrap(value))
end
function default:__tostring()
	return wrap(tostring(unwrap(self)))
end
function default:__eq(to)
	return wrap(unwrap(self) == unwrap(to))
end
function default:__lt(to)
	return wrap(unwrap(self) < unwrap(to))
end
function default:__le(to)
	return wrap(unwrap(self) <= unwrap(to))
end
function default:__len()
	return wrap(#unwrap(self))
end
table.freeze(default)

local function modify(mutator: (table) -> never)
	local clone = table.clone(default)
	mutator(clone)

	return table.freeze(clone)
end
local toCString = Functions.toCString

function Module.Init(_, Sandbox, wrapper, rules)
	if Wrapper then
		return error("Wrapper is already set.", 2)
	end

	local wmap = Sandbox.WrapMap
	Wrapper = wrapper
	wrap, unwrap = Wrapper.wrap, Wrapper.unwrap
	wrapMany, unwrapMany = Wrapper.wrapMany, Wrapper.unwrapMany

	Rules = rules

	Module.Instance = modify(function(meta)
		local get = Functions.indexInstance
		local set = Functions.newindexInstance

		local isRemoveProtected = Protection.isRemoveProtected
		local isWriteProtected = Protection.isWriteProtected
		local isReadProtected = Protection.isReadProtected

		-- Just wrapping the whole "get" function and setting __index to that would work here, but doing this is faster
		function meta:__index(index)
			self = unwrap(self)

			if isReadProtected(self) then
				return error("Property read failed: Instance is read protected", 2)
			end

			return wrap(get(self, unwrap(index)))
		end

		function meta:__newindex(index, value)
			self = unwrap(self)
			value = unwrap(value)

			if isWriteProtected(self) then
				return error("Property write failed: Instance is write protected", 2)
			end

			if type(index) == "string" and typeof(self) == "Instance" then
				-- TODO: Add this in rules.luau.
				local cIndex = toCString(index)
				if cIndex == "Parent" or cIndex == "parent" then
					if isRemoveProtected(self) then
						return error("Cannot parent " .. self.ClassName, 2)
					elseif isWriteProtected(value) then
						return error(`Cannot set parent to {value.ClassName}`, 2)
					end
				end
			end

			set(self, unwrap(index), value)
		end

		-- Map the C implementation of __index and __newindex to their sandboxed versions
		wmap[Functions.indexInstance] = meta.__index
		wmap[Functions.newindexInstance] = meta.__newindex
	end)

	Module.RBXScriptSignal = modify(function(meta)
		-- For some reason indexing methods on RBXScriptSignal's always return a unique function (check "print(game.ChildAdded.Connect) print(game.ChildAdded.Connect)")
		-- So we have to sandbox their methods here

		local methods = Rules.RBXScriptSignal
		function meta:__index(index)
			local method = methods[toCString(index)]
			if method then
				return function(...)
					return method(...)
				end
			end

			return wrap(unwrap(self)[unwrap(index)])
		end
	end)

	Module.RBXScriptConnection = modify(function(meta)
		-- The above also applies to RBXScriptConnection's

		local methods = Rules.RBXScriptConnection
		function meta:__index(index)
			local method = methods[toCString(index)]
			if method then
				return function(...)
					return method(...)
				end
			end

			return wrap(unwrap(self)[unwrap(index)])
		end
	end)

	table.freeze(setmetatable(
		Module,
		table.freeze({
			__index = function()
				return default
			end,
		})
	))
end

return Module
