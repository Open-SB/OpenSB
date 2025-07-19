local tonumber = tonumber
local error = error
local typeof = typeof
local task = task
local coroutine = coroutine

local renv = getfenv()

local ManagerCommunication = require("@shared/wm/communication")
local Errors = require("@shared/errors")
local StackTrace = require("@client/wm/stackTrace")

local Module = {}

local blockedInstances = require("./blockedInstances")

function Module.Init(_, Sandbox)
	local fmap = Sandbox.FunctionMap
	local getSandbox = Sandbox.getSandbox

	local function disable(func: () -> (), capability: string?, name: string?)
		local message = Errors.cannotCall(name or func, capability)
		fmap[func] = function()
			return error(message, 0)
		end
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/Instance
		local GetFullName = game.GetFullName
		local WaitForChild = game.WaitForChild
		local Clone = game.Clone

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#WaitForChild
		fmap[WaitForChild] = function(self, childName, timeOut)
			timeOut = tonumber(timeOut)
			if timeOut and timeOut <= 0 then
				return error("illegal argument #2 (timeOut must be greater than 0)", 0)
			end

			local sandbox = getSandbox()

			local parentThread = coroutine.running()
			local warnThread
			if not timeOut and typeof(self) == "Instance" then
				local fullName = GetFullName(self)

				local stackTrace = StackTrace.get(2)
				local filteredStackTrace = StackTrace.filter(stackTrace) -- Have to to this now due to how getRunning() works

				warnThread = task.delay(5, function()
					-- Incase the WaitForChild thread stopped yielding (could be because the function threw an error), then don't emit the warning
					if coroutine.status(parentThread) ~= "suspended" then
						return
					end

					local formatted = StackTrace.formatScriptStackTrace(filteredStackTrace)

					-- TODO: Add stacktrace
					ManagerCommunication:Send(
						"warn",
						`Infinite yield possible on '{fullName}:WaitForChild("{childName}")'`
					)
					for _, str in ipairs(formatted) do
						ManagerCommunication:Send("info", str)
					end
				end)
				sandbox.Threads[warnThread] = true
			end

			sandbox.Threads[parentThread] = true
			local child = WaitForChild(self, childName, timeOut)
			if warnThread then
				task.cancel(warnThread)
				sandbox.Threads[warnThread] = nil
			end

			return child
		end

		fmap[Clone] = function(self)
			if typeof(self) == "Instance" and blockedInstances[self.ClassName] then
				return error(Errors.createBlockedClass(self.ClassName), 0)
			end

			return Clone(self)
		end
	end

	-- https://create.roblox.com/docs/reference/engine/classes/TextChannel
	do
		local SendAsync = Instance.new("TextChannel").SendAsync

		local capability = "Chat"

		-- https://create.roblox.com/docs/reference/engine/classes/TextChannel#SendAsync
		disable(SendAsync, capability) -- SendAsync can be used to spoof commands
	end

	table.freeze(Module)
end

return Module
