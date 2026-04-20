local StudioTestService = game:GetService("StudioTestService")
local RunService = game:GetService("RunService")

-- "ExecutePlayModeAsync: can only be called from the edit DataModel" (?)
-- This seems to fix it though
while task.wait(0.1) do
	-- doesn't seem to do anything, but better be safe than sorry
	if not RunService:IsEdit() then
		continue
	end

	if
		pcall(function()
			local testResult = StudioTestService:ExecutePlayModeAsync("OpenSBSuite")
			print("[Plugin]", testResult)
		end)
	then
		break
	end
end
