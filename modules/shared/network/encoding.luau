local MessagePack = require("@shared/msgpack")
local Blake3 = require("@shared/crypto/blake3")
local Base64 = require("@shared/crypto/base64")
local XXH32 = require("@shared/crypto/XXH32")

local INSTANCE_EXTENSION_TYPE = 12 -- 0x0c

local Module = {}

-- Returns a u32
local function computeDecentChecksum(instance: Instance): number
	-- We should only use datapoints here that are actually garuanteed to be shared with the server
	-- So something like :GetFullName() might seem ok, but it's return could actually differ on the client and server (as the client could change the instance's parent or name).
	--
	-- Only other datapoint I could think of would be the instance's creation date, but keeping track of that on all instances is expensive.
	return XXH32(buffer.fromstring(`{instance.ClassName}`))
end

-- Returns a MessagePack encoded string blob and a list of instances to be shipped alongside the blob.
-- This function MAY error, as buffer operations can fail if there is not enough memory on the server.
-- You should also wrap this function in a pcall.
function Module.encode(data: any): (buffer, { Instance })
	-- do not allow outside callers to mess with instance table
	local index = 1
	local function encode(data: any, instanceArray: { Instance }, first: boolean)
		local datatype = typeof(data)

		if datatype == "table" then
			local new = {}

			for key, value in pairs(data) do
				new[key] = encode(value, instanceArray, false)
			end

			data = new
		elseif datatype == "Instance" then
			local extensionData = buffer.create(8)
			buffer.writeu32(extensionData, 0, computeDecentChecksum(data))
			buffer.writeu32(extensionData, 4, index)

			local extension = MessagePack.Extension.new(INSTANCE_EXTENSION_TYPE, extensionData)

			table.insert(instanceArray, data)
			index += 1

			data = extension
		end

		return data, instanceArray
	end

	local clone, instanceArray = encode(data, {}, true)
	return MessagePack.encode(clone), instanceArray
end

-- Decodes a MessagePack blob with an instance array, returning the decoded data.
-- This function CAN and WILL error if given invalid data. Please wrap in a pcall.
function Module.decode(data: buffer, instanceArray: { Instance }): any
	local result = MessagePack.decode(data)

	local function decode(data: any)
		if typeof(data) == "table" then
			if data._msgpackType ~= nil and data.type == INSTANCE_EXTENSION_TYPE then
				local extensionData: buffer = data.data
				local index = buffer.readu32(extensionData, 4)
				local instance = instanceArray[index]

				if not instance then
					error("Integrity check failed: instanceArray[index] is nil", 2)
				end

				if typeof(instance) ~= "Instance" then
					error("Integrity check failed: instanceArray[index] returned a non-instance value", 2)
				end

				local checksum = buffer.readu32(extensionData, 0)
				local expected = computeDecentChecksum(instance)

				if checksum ~= expected then
					error(
						`Integrity check failed: hash check failed! expected {expected} but got {checksum} from extension data [0-4]`,
						2
					)
				end

				return instance
			end

			for key, value in pairs(data) do
				data[key] = decode(value)
			end
		end

		return data
	end

	return decode(result)
end

return table.freeze(Module)
