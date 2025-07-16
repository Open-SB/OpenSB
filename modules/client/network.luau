local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local services = require("shared/network/services")
local RequestMethods = require("shared/network/requestMethods")
local ServerRequestMethod = RequestMethods.Server
local ClientRequestMethod = RequestMethods.Client

local Log = require("shared/log")
local Functions = require("shared/functions")
local HashLib = require("shared/hashLib")
local Signal = require("shared/signal")

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
	if requestType == ClientRequestMethod.Event then
		-- Minimize the yielding time for the server if the client is calculating stuff
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
	elseif requestType == ClientRequestMethod.InvokeResult then
		-- Minimize the yielding time for the server if the client is calculating stuff
		task.spawn(function(id, ...)
			local signal = invokeResults[id]
			if not signal then
				return
			end

			if not isValidRequestKey(requestKey) then
				return
			end

			signal:Fire(...)
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
			task.spawn(remote.InvokeServer, remote, ServerRequestMethod.Event, requestKey, eventName, ...)
		end
	end, ...)
end

function Network:InvokeServer(functionName: string, ...)
	while keyLocked ~= true do
		task.wait()
	end

	local requestKey, id = generateRequestKey(), nil

	repeat
		id = Functions.randomString(8)
	until invokeResults[id] == nil

	local signal = Signal.new()
	invokeResults[id] = signal

	while next(remotes) == nil do
		task.wait()
	end

	for remote, _ in remotes do
		task.spawn(remote.InvokeServer, remote, ServerRequestMethod.Invoke, requestKey, id, functionName, ...)
	end

	return (function(...)
		invokeResults[id] = nil
		signal:Destroy()

		return ...
	end)(signal:Wait())
end

local function connectRemote(service: Instance, remote: RemoteFunction)
	if remote:GetAttribute(attributeName) ~= attributeValue then
		return
	end

	if not key then
		-- TODO: Check signature of key

		-- We check if the timing is above your ping * 5, as it would take at minimum your ping * 6 to do a man in the middle attack.
		-- Even if this check fails, it would get rechecked the next time the remote refits.
		-- (Not the most reliable way of detecting a mitm attack.)

		local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
		local newKey, requestTime = remote:InvokeServer(ServerRequestMethod.KeyExchange), os.clock() - requestStart

		if not newKey then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (no key exchanged)\nIf the issue does not resolve then try rejoining`
			)
		end

		if ping > 0 and requestTime > ping * 5 then
			return Log.warn(
				`Key exchange failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping * 2}])`
			)
		end

		key = newKey
	end

	local requestStart, ping = os.clock(), localPlayer:GetNetworkPing()
	local requestKey, requestTime =
		remote:InvokeServer(ServerRequestMethod.Handshake, generateRequestKey()), os.clock() - requestStart

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

	if ping > 0 and requestTime > ping * 5 then
		return Log.warn(
			`Handshake failed on remote "{remote:GetFullName()}" (timing check: [{requestTime}, {ping * 2}])`
		)
	end

	remotes[remote] = service
	remote.OnClientInvoke = onRequest
end

function Network:Init(attribute: {})
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

	-- Already leaked magic 🤯 (I know better methods but I don't want to leak them ;) - EwDev)
	local args: any = table.create(80, task.defer)
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
end

return Network
