local table = table
local typeof = typeof
local error = error
local type = type
local task = task
local tonumber = tonumber
local coroutine = coroutine
local debug = debug

local ManagerCommunication = require("shared/wm/communication")
local Functions = require("shared/functions")

local renv = getfenv()
local removeProtectedClasses = table.freeze({
	Player = true,
	PlayerGui = true,
	-- Backpack shouldn't be put in this list as you can create them with Instance.new()
})

local Module = {}
Module.RemoveProtectedClasses = removeProtectedClasses

function Module.Init(_, Sandbox, Wrapper, Reflection)
	local wmap = Sandbox.WrapMap
	local getSandbox = Sandbox.getSandbox
	local assertTerminated = Sandbox.assertTerminated

	local wrap, unwrap = Wrapper.wrap, Wrapper.unwrap
	local wrapMany, unwrapMany = Wrapper.wrapMany, Wrapper.unwrapMany
	local typeofWrapped = Wrapper.typeofWrapped

	-- Map the C implementation of __index and __newindex to their sandboxed versions
	wmap[Functions.indexInstance] = Reflection.Instance.__index
	wmap[Functions.newindexInstance] = Reflection.Instance.__newindex

	do -- https://create.roblox.com/docs/reference/engine/classes/Instance
		local ClearAllChildren = game.ClearAllChildren
		local Destroy = game.Destroy
		local GetFullName = game.GetFullName
		-- selene: allow(deprecated)
		local Remove = game.Remove
		local WaitForChild = game.WaitForChild

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#ClearAllChildren
		wmap[ClearAllChildren] = function(self)
			self = unwrap(self)
			if self == renv.game:GetService("Players") then -- Contains Player's
				return error("Cannot ClearAllChildren() Players", 2)
			elseif typeof(self) == "Instance" and self.ClassName == "Player" then -- Contains PlayerGui's
				return error("Cannot ClearAllChildren() Player", 2)
			end

			ClearAllChildren(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#Destroy
		wmap[Destroy] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" and removeProtectedClasses[self.ClassName] then
				return error("Cannot Destroy() " .. self.ClassName, 2)
			end

			Destroy(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#Remove
		wmap[Remove] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" and removeProtectedClasses[self.ClassName] then
				return error("Cannot Remove() " .. self.ClassName, 2)
			end

			Remove(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#WaitForChild
		wmap[WaitForChild] = function(self, childName, timeOut)
			timeOut = tonumber(timeOut)
			if timeOut and timeOut <= 0 then
				return error("illegal argument #2 (timeOut must be greater than 0)", 2)
			end

			local sandbox = getSandbox()
			assertTerminated(sandbox)

			self = unwrap(self)

			local thread
			if not timeOut and typeof(self) == "Instance" then
				thread = task.delay(
					5,
					ManagerCommunication.Send,
					ManagerCommunication,
					"warn",
					sandbox.Owner,
					`Infinite yield possible on '{GetFullName(self)}:WaitForChild("{childName}")'`
				)
				sandbox.Threads[thread] = true
			end

			sandbox.Threads[coroutine.running()] = true
			local child = WaitForChild(self, childName, timeOut)
			if thread then
				task.cancel(thread)
				sandbox.Threads[thread] = nil
			end

			assertTerminated(sandbox)
			return child
		end
	end

	do -- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal
		local RBXScriptSignal = renv.game.AncestryChanged
		local Connect = RBXScriptSignal.Connect
		local ConnectParallel = RBXScriptSignal.ConnectParallel
		local Once = RBXScriptSignal.Once
		local Wait = RBXScriptSignal.Wait

		local methods = {}

		-- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal#Connect
		methods.Connect = function(self, func)
			if type(func) ~= "function" then
				return error("Attempt to connect failed: Passed value is not a function", 2)
			end

			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local connection = Connect(unwrap(self), function(...)
				assertTerminated(sandbox)
				func(wrapMany(...))
			end)
			sandbox.Connections[connection] = true

			return wrap(connection)
		end
		methods.connect = methods.Connect

		-- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal#ConnectParallel
		methods.ConnectParallel = function(self, func)
			if type(func) ~= "function" then
				return error("Attempt to connect failed: Passed value is not a function", 2)
			end

			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local connection = ConnectParallel(unwrap(self), function(...)
				assertTerminated(sandbox)
				func(wrapMany(...))
			end)
			sandbox.Connections[connection] = true

			return wrap(connection)
		end
		methods.connectParallel = methods.ConnectParallel

		-- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal#Once
		methods.Once = function(self, func)
			if type(func) ~= "function" then
				return error("Attempt to connect failed: Passed value is not a function", 2)
			end

			local sandbox = getSandbox()
			assertTerminated(sandbox)

			local connection
			connection = Once(unwrap(self), function(...)
				sandbox.Connections[connection] = nil

				assertTerminated(sandbox)
				func(wrapMany(...))
			end)
			sandbox.Connections[connection] = true

			return wrap(connection)
		end

		-- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal#Wait
		methods.Wait = function(self)
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			return (function(...)
				assertTerminated(sandbox)
				return ...
			end)(wrapMany(Wait(unwrap(self))))
		end

		Module.RBXScriptSignal = table.freeze(methods)
	end

	do -- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptConnection
		local RBXScriptConnection = renv.game.AncestryChanged:Once(function() end)
		local Disconnect = RBXScriptConnection.Disconnect
		Disconnect(RBXScriptConnection)

		local methods = {}

		-- https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptConnection#Disconnect
		methods.Disconnect = function(self)
			self = unwrap(self)
			Disconnect(self)
			getSandbox().Connections[self] = nil
		end
		methods.disconnect = methods.Disconnect

		Module.RBXScriptConnection = table.freeze(methods)
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/Players
		local Players = renv.game:GetService("Players")

		-- https://create.roblox.com/docs/reference/engine/classes/Players#BanAsync
		wmap[Players.BanAsync] = function()
			return error("BanAsync() is disabled", 2)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Players#UnbanAsync
		wmap[Players.UnbanAsync] = function()
			return error("BanAsync() is disabled", 2)
		end
	end

	task.spawn(function() -- https://create.roblox.com/docs/reference/engine/classes/Player
		local Player = renv.game:GetService("Players"):FindFirstChildOfClass("Player")
			or renv.game:GetService("Players").PlayerAdded:Wait()

		-- https://create.roblox.com/docs/reference/engine/classes/Player#Kick
		wmap[Player.Kick] = function()
			return error("Kick() is disabled", 2)
		end
	end)

	do -- https://create.roblox.com/docs/reference/engine/classes/Debris
		local Debris = renv.game:GetService("Debris")
		local AddItem = Debris.AddItem

		-- https://create.roblox.com/docs/reference/engine/classes/Debris#AddItem
		wmap[AddItem] = function(self, item, ...)
			item = unwrap(item)
			if typeof(item) == "Instance" and removeProtectedClasses[item.ClassName] then
				return error("Cannot AddItem() " .. item.ClassName, 2)
			end

			AddItem(unwrap(self), item, unwrapMany(...))
		end
	end

	table.freeze(Module)
end

return Module
