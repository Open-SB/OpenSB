local table = table
local typeof = typeof
local error = error
local type = type
local task = task
local tonumber = tonumber
local coroutine = coroutine
local debug = debug

local ManagerCommunication = require("@shared/wm/communication")
local Wrapper = require("./wrapper")
local Protection = require("@shared/wm/protection")
local Functions = require("@shared/functions")
local Errors = require("@shared/errors")

local renv = getfenv()

local Module = {}

local blockedInstances = require("./blockedInstances")

function Module.Init(_, Sandbox)
	local wmap = Sandbox.WrapMap
	local getSandbox = Sandbox.getSandbox
	local assertTerminated = Sandbox.assertTerminated

	local wrap, unwrap = Wrapper.wrap, Wrapper.unwrap
	local wrapMany, unwrapMany = Wrapper.wrapMany, Wrapper.unwrapMany

	local isRemoveProtected = Protection.isRemoveProtected
	local isWriteProtected = Protection.isWriteProtected
	local isReadProtected = Protection.isReadProtected

	local function disable(func: () -> (), capability: string?, name: string?)
		local message = Errors.cannotCall(name or func, capability)
		wmap[func] = function()
			return error(message, 0)
		end
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/Instance
		local ClearAllChildren = game.ClearAllChildren
		local Destroy = game.Destroy
		local GetFullName = game.GetFullName
		-- selene: allow(deprecated)
		local Remove = game.Remove
		local WaitForChild = game.WaitForChild
		local Clone = game.Clone

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#ClearAllChildren
		wmap[ClearAllChildren] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" then
				for _, child in ipairs(self:GetChildren()) do
					if isRemoveProtected(child) then
						return error(Errors.lockedParent(child), 0)
					end
				end
			end

			ClearAllChildren(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#Destroy
		wmap[Destroy] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" and isRemoveProtected(self) then
				return error(Errors.lockedParent(self), 0)
			end

			Destroy(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#Remove
		wmap[Remove] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" and isRemoveProtected(self) then
				return error(Errors.lockedParentSet(self, nil), 0)
			end

			Remove(self)
		end

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#WaitForChild
		wmap[WaitForChild] = function(self, childName, timeOut)
			timeOut = tonumber(timeOut)
			if timeOut and timeOut <= 0 then
				return error("illegal argument #2 (timeOut must be greater than 0)", 0)
			end

			local sandbox = getSandbox()
			assertTerminated(sandbox)

			self = unwrap(self)

			local parentThread = coroutine.running()
			local warnThread
			if not timeOut and typeof(self) == "Instance" then
				local fullName = GetFullName(self)
				warnThread = task.delay(5, function()
					-- Incase the WaitForChild thread stopped yielding (could be because the function threw an error), then don't emit the warning
					if coroutine.status(parentThread) ~= "suspended" then
						return
					end

					-- TODO: Add stacktrace
					ManagerCommunication:Send(
						"warn",
						sandbox.Owner,
						`Infinite yield possible on '{fullName}:WaitForChild("{childName}")'`
					)
				end)
				sandbox.Threads[warnThread] = true
			end

			sandbox.Threads[parentThread] = true
			local child = WaitForChild(self, childName, timeOut)
			if warnThread then
				task.cancel(warnThread)
				sandbox.Threads[warnThread] = nil
			end

			assertTerminated(sandbox)

			return wrap(child)
		end

		wmap[Clone] = function(self)
			self = unwrap(self)
			if typeof(self) == "Instance" and (blockedInstances[self.ClassName] or isReadProtected(self)) then
				return error(Errors.createBlockedClass(self.ClassName), 0)
			end

			return wrap(Clone(self))
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
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			if type(func) ~= "function" then
				-- TODO: Add stacktrace
				ManagerCommunication:Send("error", sandbox.Owner, Errors.connectNonFunction())
				return Connect(unwrap(self))
			end

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
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			if type(func) ~= "function" then
				-- TODO: Add stacktrace
				ManagerCommunication:Send("error", sandbox.Owner, Errors.connectNonFunction())
				return ConnectParallel(unwrap(self))
			end

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
			local sandbox = getSandbox()
			assertTerminated(sandbox)

			if type(func) ~= "function" then
				-- TODO: Add stacktrace
				ManagerCommunication:Send("error", sandbox.Owner, Errors.connectNonFunction())
				return Once(unwrap(self))
			end

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
		disable(Players.BanAsync)

		-- https://create.roblox.com/docs/reference/engine/classes/Players#UnbanAsync
		disable(Players.UnbanAsync)

		-- https://create.roblox.com/docs/reference/engine/classes/Players#GetBanHistoryAsync
		disable(Players.GetBanHistoryAsync)
	end

	task.spawn(function() -- https://create.roblox.com/docs/reference/engine/classes/Player
		local Player = renv.game:GetService("Players"):FindFirstChildOfClass("Player")
			or renv.game:GetService("Players").PlayerAdded:Wait()

		-- https://create.roblox.com/docs/reference/engine/classes/Player#Kick
		disable(Player.Kick)
	end)

	do -- https://create.roblox.com/docs/reference/engine/classes/Debris
		local Debris = renv.game:GetService("Debris")
		local AddItem = Debris.AddItem

		-- https://create.roblox.com/docs/reference/engine/classes/Debris#AddItem
		wmap[AddItem] = function(self, item, lifetime)
			item = unwrap(item)
			lifetime = unwrap(lifetime)

			if typeof(item) == "Instance" and isRemoveProtected(item) then
				local cLifetime = Functions.toCDouble(lifetime)
				if cLifetime then
					local sandbox = getSandbox()
					task.delay(cLifetime, function()
						local msg = Errors.lockedParent(item)
						ManagerCommunication:Send("warn", sandbox.Owner, msg)
						warn(msg)
					end)

					return
				end
			end

			AddItem(unwrap(self), item, lifetime)
		end
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/TeleportService
		local TeleportService = renv.game:GetService("TeleportService")

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#Teleport
		disable(TeleportService.Teleport)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#TeleportToPlaceInstance
		disable(TeleportService.TeleportToPlaceInstance)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#TeleportToPrivateServer
		disable(TeleportService.TeleportToPrivateServer)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#TeleportToSpawnByName
		disable(TeleportService.TeleportToSpawnByName)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#ReserveServer
		disable(TeleportService.ReserveServer)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#TeleportAsync
		disable(TeleportService.TeleportAsync)

		-- https://create.roblox.com/docs/reference/engine/classes/TeleportService#TeleportPartyAsync
		disable(TeleportService.TeleportPartyAsync)
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/InsertService
		local InsertService = renv.game:GetService("InsertService")

		-- https://create.roblox.com/docs/reference/engine/classes/InsertService#LoadAsset
		disable(InsertService.LoadAsset)

		-- https://create.roblox.com/docs/reference/engine/classes/InsertService#LoadAssetVersion
		disable(InsertService.LoadAssetVersion)
	end

	table.freeze(Module)
end

return Module
