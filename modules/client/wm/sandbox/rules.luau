local tonumber = tonumber
local error = error
local typeof = typeof
local task = task
local coroutine = coroutine

local renv = getfenv()

local ManagerCommunication = require("shared/wm/communication")

local Module = {}

function Module.Init(_, Sandbox)
	local fmap = Sandbox.FunctionMap
	local getSandbox = Sandbox.getSandbox

	local function disable(func: () -> (), name: string?)
		local funcName = name or debug.info(func, "n") or ""
		local message = funcName .. "() is disabled"

		fmap[func] = function()
			return error(message, 2)
		end
	end

	do -- https://create.roblox.com/docs/reference/engine/classes/Instance
		local GetFullName = game.GetFullName
		local WaitForChild = game.WaitForChild

		-- https://create.roblox.com/docs/reference/engine/classes/Instance#WaitForChild
		fmap[WaitForChild] = function(self, childName, timeOut)
			timeOut = tonumber(timeOut)
			if timeOut and timeOut <= 0 then
				return error("illegal argument #2 (timeOut must be greater than 0)", 2)
			end

			local sandbox = getSandbox()

			local parentThread = coroutine.running()
			local warnThread
			if not timeOut and typeof(self) == "Instance" then
				local fullName = GetFullName(self)
				warnThread = task.delay(5, function()
					-- Incase the WaitForChild thread stopped yielding (could be because the function threw an error), then don't emit the warning
					if coroutine.status(parentThread) ~= "suspended" then
						return
					end

					-- TODO: Add stacktraces to warnings
					ManagerCommunication:Send(
						"warn",
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

			return child
		end
	end

	table.freeze(Module)
end

return Module
