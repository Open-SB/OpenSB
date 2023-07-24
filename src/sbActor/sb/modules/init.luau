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
local moduleLookup: { [string]: any } = {}

for _, module in ipairs(modules) do
	moduleLookup[module.Name] = loadingState -- We set a module to a loading state so if another module tries to load this module we know we can yield

	task.defer(function()
		local wrappedModule: { any } = require(module)
		local Module = wrappedModule[1]

		table.clear(wrappedModule)
		module:Destroy()

		-- We set the module to a metatable to prevent iterating the module, writing to it (while still allowing the module to write to it)
		local proxy = newproxy(true)
		local metatable = getmetatable(proxy)
		metatable.__metatable = "The metatable is locked"

		metatable.__index = function(_, index: string): any
			return Module[index]
		end

		metatable.__newindex = function()
			error("Modules are readonly.", 2)
		end

		moduleLookup[module.Name] = proxy
		loadedModules += 1
	end)
end

local locked = false
function Modules:Lock() -- We call this after the game has loaded so modules can't be obtained anymore
	locked = true
	table.clear(moduleLookup) -- Just incase
end

function Modules.require(name: string): any
	if locked then
		return error("Modules are locked.", 2)
	end

	if not moduleLookup[name] then
		return error(`"{name}" is an invalid module name.`, 2)
	end

	-- Wait for module to finish loading
	while moduleLookup[name] == loadingState do
		task.wait()
	end

	return moduleLookup[name]
end

function Modules.waitForModulesToLoad()
	while totalModules > loadedModules do
		task.wait()
	end
end

return table.freeze(Modules)
