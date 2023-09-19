--!strict
local setfenv = setfenv
local table = table
local script = script
local ipairs = ipairs
local newproxy = newproxy
local error = error
local require = require
local task = task
local getmetatable = getmetatable

setfenv(1, {})

local Modules = {}

local modules = script:GetChildren()
script = nil

local loadingState = newproxy()
local totalModules, loadedModules = #modules, 0
local moduleLookup: { [string | Instance]: any } = {}

for _, module in ipairs(modules) do
	-- We set a module to a loading state so if another module tries to load this module we know we can yield
	moduleLookup[module.Name] = loadingState
	moduleLookup[module] = loadingState

	task.defer(function()
		local wrappedModule: { any } = require(module)
		local Module = wrappedModule[1]

		table.clear(wrappedModule)
		module:Destroy()

		-- We set the module to a metatable to prevent iterating and writing to the module (while still allowing the module to write to itself)
		local proxy = newproxy(true)
		local metatable = getmetatable(proxy)
		metatable.__metatable = "The metatable is locked"

		metatable.__index = function(_, index): any
			return Module[index]
		end

		metatable.__newindex = function()
			return error("Modules are readonly.", 2)
		end

		moduleLookup[module.Name] = proxy
		moduleLookup[module] = proxy

		loadedModules += 1
	end)
end

local locked = false
function Modules:Lock() -- We call this after the game has loaded so modules can't be obtained anymore
	locked = true

	-- Just incase
	Modules.Lock = function() end
	Modules.require = function() end
	table.clear(moduleLookup)
end

function Modules.require(nameOrInstance: string | Instance): any
	if locked then
		return error("Modules are locked.", 2)
	end

	if not moduleLookup[nameOrInstance] then
		return error(`"{nameOrInstance}" is an invalid module.`, 2)
	end

	-- Wait for module to finish loading
	while moduleLookup[nameOrInstance] == loadingState do
		task.wait()
	end

	return moduleLookup[nameOrInstance]
end

function Modules.waitForModulesToLoad()
	while totalModules > loadedModules do
		task.wait()
	end
end

local proxy = newproxy(true)
local metatable = getmetatable(proxy)
metatable.__metatable = "The metatable is locked"

metatable.__index = function(_, index): any
	return Modules[index]
end

metatable.__newindex = function()
	error("attempt to modify a readonly table", 2)
end

return proxy
