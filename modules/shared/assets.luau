local Log = require("shared/log")

local Assets = {}
Assets.assets = {}

function Assets:get(asset)
	assert(Assets.assets[asset], `Invalid asset "{asset}".`)
	return Assets.assets[asset]
end

function Assets:Init(folderParent, folderName)
	Log.debug("Fetching assets...")

	-- Set a timeout warning the user if fetching assets took longer than expected (may be caused by other scripts tampering).
	local timeoutThread = task.delay(5, Log.warn, "Fetching assets took longer than expected (try rejoining?).")
	local folder = folderParent:WaitForChild(folderName)

	-- On the client all assets may not have loaded yet (assets will be removed on client at some point).
	local expectedDescendants = folder:GetAttribute("_descendants")
	if expectedDescendants then
		while true do
			local descendants = #folder:GetDescendants()
			Log.debug(`Fetching assets ({descendants} / {expectedDescendants})...`)

			if descendants >= expectedDescendants then
				break
			end

			folder.DescendantAdded:Wait()
		end
	end

	-- Cancel the warn timeout.
	task.cancel(timeoutThread)

	for _, child in ipairs(folder:GetChildren()) do
		Assets.assets[child.Name] = child:Clone()
	end

	table.freeze(Assets.assets)
	folder:Destroy()
end

return Assets
