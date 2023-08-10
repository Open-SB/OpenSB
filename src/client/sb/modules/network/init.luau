--!strict
local Instance = Instance
local setfenv = setfenv
local script = script
local require = require
local game = game
local error = error
local unpack = unpack
local task = task
local table = table
local os = os
local pcall = pcall
local ipairs = ipairs
local type = type
local next = next

setfenv(1, {})

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local Modules = require(script.Parent)
local services = table.clone(require(script:WaitForChild("services")))
script = nil

local Log = Modules.require("log")
local Functions = Modules.require("functions")
local HashLib = Modules.require("hashLib")

local localPlayer = Players.LocalPlayer
local attributeName, attributeValue

local Network = {}

local registeredEvents: { [string]: (...unknown) -> nil } = {}
function Network:RegisterEvent(name: string, callback: (...unknown) -> nil)
	if registeredEvents[name] then
		Log.warn(`Network event "{name}" was overwritten.`)
	end

	registeredEvents[name] = callback
end

local key: string?
local keyLocked = false
local usedHashes: { [string]: boolean } = {} -- Prevent replay attacks

local function isValidRequestKey(requestKey): boolean
	if type(requestKey) ~= "table" then
		return false
	end

	local hash, salt = requestKey[1], requestKey[2]
	if type(hash) ~= "string" or type(salt) ~= "string" then
		return false
	end

	if usedHashes[hash] then
		return false
	end

	if hash == HashLib.hmac(HashLib.sha256, key, salt) then
		usedHashes[hash] = true

		return true
	end

	return false
end

local function generateRequestKey(): { string }
	while key == nil do
		task.wait()
	end

	local salt = Functions.randomString(64)
	local hash = HashLib.hmac(HashLib.sha256, key, salt)

	if usedHashes[hash] then -- It's very unlikely this would ever happen, but ¯\_(ツ)_/¯
		return generateRequestKey()
	end

	usedHashes[hash] = true
	return { hash, salt }
end

local remotes: { [RemoteFunction]: Instance } = {}
local invokeResults: { [string]: BindableEvent } = {}

local function onRequest(requestType, requestKey, ...)
	if requestType == 0 then -- Event
		-- Minimize the yielding time for the server if the server is calculating stuff
		task.spawn(function(eventName, ...)
			local callback = registeredEvents[eventName]
			if not callback then
				return
			end

			if not isValidRequestKey(requestKey) then
				return
			end

			callback(...)
		end, ...)
	elseif requestType == 1 then -- Invoke result
		-- Minimize the yielding time for the server if the server is calculating stuff
		task.spawn(function(id, ...)
			local bindable = invokeResults[id]
			if not bindable then
				return
			end

			if not isValidRequestKey(requestKey) then
				return
			end

			bindable:Fire(...)
		end, ...)
	end
end

function Network:FireServer(eventName: string, ...)
	task.spawn(function(...)
		while keyLocked ~= true do
			task.wait()
		end

		local requestKey = generateRequestKey()
		while next(remotes) == nil do
			task.wait()
		end

		for remote, _ in remotes do
			task.spawn(
				remote.InvokeServer,
				remote,
				2, -- Event
				requestKey,
				eventName,
				...
			)
		end
	end, ...)
end

function Network:InvokeServer(functionName: string, ...)
	while keyLocked ~= true do
		task.wait()
	end

	local requestKey, id = generateRequestKey(), nil

	repeat
		id = Functions.randomString(32)
	until invokeResults[id] == nil

	local bindable = Instance.new("BindableEvent")
	invokeResults[id] = bindable

	while next(remotes) == nil do
		task.wait()
	end

	for remote, _ in remotes do
		task.spawn(
			remote.InvokeServer,
			remote,
			3, -- Invoke
			requestKey,
			id,
			functionName,
			...
		)
	end

	return (function(...)
		invokeResults[id] = nil
		bindable:Destroy()

		return ...
	end)(bindable.Event:Wait())
end

local function connectRemote(service: Instance, remote: RemoteFunction)
	if remote:GetAttribute(attributeName) ~= attributeValue then
		return
	end

	if not key then
		-- TODO: Check signature of key

		-- We check if the timing is above your ping * 2, as it would take at minimum your ping * 3 to do a man in the middle attack
		-- Even if this check fails, it would get rechecked the next time the remote refits

		local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
		local newKey, requestTime = remote:InvokeServer(
			0 -- Key exchange
		), os.clock() - requestStart

		if not newKey then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (no key exchanged)\nIf the issue does not resolve then try rejoining`
			)
		end

		if ping > 0 and requestTime > ping * 2 then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping}])`
			)
		end

		key = newKey
	end

	local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
	local requestKey, requestTime =
		remote:InvokeServer(
			1, -- Handshake
			generateRequestKey()
		), os.clock() - requestStart

	-- If the handshake fails on the server then the client has an incorrect key, so we redo the key exchange
	if not requestKey then
		Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (server key check)\nRetrieving new key...`)

		key = nil
		return connectRemote(service, remote)
	end

	keyLocked = true

	-- We still check if the key is valid before performing a timing check, so if the key was valid it would get invalidated
	if not isValidRequestKey(requestKey) then
		return Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (key check)`)
	end

	if ping > 0 and requestTime > ping * 2 then
		return Log.warn(`Handshake failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping}])`)
	end

	remotes[remote] = service
	remote.OnClientInvoke = onRequest
end

function Network.init(attribute: {})
	Network.init = Functions.empty -- Prevent future changes
	attributeName, attributeValue = unpack(attribute)

	for _, service in ipairs(services) do
		service.ChildAdded:Connect(function(child)
			if child.ClassName == "RemoteFunction" then
				connectRemote(service, child :: RemoteFunction)
			end
		end)

		for _, child in ipairs(service:GetChildren()) do
			if child.ClassName == "RemoteFunction" then
				task.spawn(connectRemote, service, child :: RemoteFunction)
			end
		end
	end
end

-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
local args = table.create(80, task.defer)
table.insert(args, function()
	for remote, service in remotes do
		if remote.Parent ~= service then
			remotes[remote] = nil

			continue
		end

		remote.OnClientInvoke = onRequest
	end
end)

RunService.PostSimulation:Connect(function()
	pcall(unpack(args))
end)

return { Network }
