local __start = os.clock()

local Log = require("shared/log")

--[[
	We bundle all modules into one script, which all get inlined above this one.

	But due https://github.com/seaofvoices/darklua/pull/147, all bundled modules are no longer ran on startup.
	Here we load all bundled modules before modying the env and destroying the script (so the modules can get whatever they need before we remove them).
	
	This is a kinda hacky solution, and might break in a future darklua release.
	But it keeps the old behavior darklua used to had. Which was useful for clearing the env and destroying the script.
]]

-- do
-- 	Log.debug("Loading modules...")

-- 	-- selene: allow(undefined_variable)
-- 	local modules = __DARKLUA_BUNDLE_MODULES -- Check .darklua.json
-- 	for name, _ in modules do
-- 		if name ~= "cache" and name ~= "load" then -- darklua places all modules, the load function, and cache table in the same table (we don't want to call cache and load).
-- 			modules.load(name)
-- 		end
-- 	end
-- end

-- setfenv(1, {})

-- Fetch assets and destroy script
local sbActor = script.Parent
local assetsFolder = sbActor.Parent:WaitForChild("assets")

do
	local attributeChanged = sbActor:GetAttributeChangedSignal("canDestroy")
	while not sbActor:GetAttribute("canDestroy") do
		attributeChanged:Wait()
	end
end

do
	local thread = coroutine.running()
	task.defer(
		function() -- Defer has a small yield (under a frame) allowing us to delete the script (instances can't change their parent instantly after there were parented / created)
			sbActor:Destroy()
			script:Destroy()
			script = nil

			coroutine.resume(thread)
		end
	)

	coroutine.yield() -- Yield thread until script has been destroyed, so events dont get connected in the process (then disconnected by :Destroy())
end

local Assets = require("shared/assets")
Assets:Init(assetsFolder)

local clientScripts = Assets:get("clientScripts")
local clientAssets = clientScripts:WaitForChild("assets")
clientAssets:SetAttribute("_descendants", #clientAssets:GetDescendants())

-- Services and modules
local Players = game:GetService("Players")

Log.debug("Loading modules...")

local Network = require("server/network")
local Commands = require("server/commands")
local Chat = require("server/chat")
local World = require("server/world")
local Functions = require("shared/functions")

Network:Init()
Chat:Init()
Commands:Init()

Log.debug("Loading systems...") -- Maybe we should move these into their own modules?

-- Player system
do
	local function disconnectPlayer() end

	local function connectPlayer(player: Player)
		Log.debug(`Checking if {player.Name} can join...`)

		if not _G.DEV and player.AccountAge < 7 then
			Log.debug(`{player.Name}'s account age is too young (<7).`)
			player:Kick("Your account age has to be atleast one week old to play this game.")

			-- TODO: Alert to others why they couldnt join

			return
		end

		Log.debug(`Checking ban on {player.Name}...`)
		-- TODO: Ban check

		do
			Log.debug(`Loading SB client on {player.Name}...`)

			local playerGui = player:FindFirstChildOfClass("PlayerGui")
			if not playerGui then
				Log.debug(`{player.Name} had no player gui.`)
				player:Kick("PlayerGui was not found while loading.")

				return
			end

			local screenGui = clientScripts:Clone()
			screenGui.Name = Functions.randomInstanceName()
			screenGui.Archivable = false

			local sbClientActor = screenGui:WaitForChild("sbActor")
			sbClientActor.Archivable = false

			local sbClient = sbClientActor:WaitForChild("sb")
			sbClient.Name = Functions.randomInstanceName()
			sbClient.Archivable = false

			local sandboxClient = screenGui:WaitForChild("sandbox")
			sandboxClient.Name = Functions.randomInstanceName()
			sandboxClient.Archivable = false

			-- Tranfer the remote attribute to find the remote
			sbClient:SetAttribute(Network.attributeName, Network.attributeValue)

			screenGui.Parent = playerGui
			task.delay(10, function()
				screenGui:Destroy()
				sbClientActor:Destroy()
				sbClient:Destroy()
				sandboxClient:Destroy()
			end)
		end
	end

	Players.PlayerAdded:Connect(connectPlayer)
	Players.PlayerRemoving:Connect(disconnectPlayer)

	for _, player: Player in ipairs(Players:GetPlayers()) do
		task.spawn(connectPlayer, player)
	end
end

-- Finalize
Log.debug("Finalizing...")

World:Init()
Players.CharacterAutoLoads = true
for _, player: Player in ipairs(Players:GetPlayers()) do
	task.defer(player.LoadCharacter, player)
end

Log.print(`Loaded in {math.round((os.clock() - __start) * 1000)}ms.`)

return nil
