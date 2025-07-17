local MessagePack = require("@shared/network/msgpack")
local Blake3 = require("@shared/network/blake3")
local Base64 = require("@shared/network/base64")

local INSTANCE_EXTENSION_TYPE = 12 -- 0x0c

local Module = {}

local function computeDecentHash(instance: Instance)
	return Blake3.Digest(buffer.fromstring(`{instance:GetFullName()}{instance.ClassName}`), 16)
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
			local extensionData = buffer.create(20)
			buffer.copy(extensionData, 0, computeDecentHash(data), 0)
			buffer.writeu32(extensionData, 16, index)

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
				local index = buffer.readu32(extensionData, 16)
				local instance = instanceArray[index]

				if not instance then
					error("Integrity check failed: instanceArray[index] is nil", 2)
				end

				if typeof(instance) ~= "Instance" then
					error("Integrity check failed: instanceArray[index] returned a non-instance value", 2)
				end

				local hashAsString = buffer.readstring(extensionData, 0, 16)
				local computedHash = computeDecentHash(instance)

				if hashAsString ~= buffer.tostring(computedHash) then
					local computedAsBase64 = buffer.tostring(Base64.Encode(computedHash))
					local hashAsBase64 = buffer.tostring(Base64.Encode(buffer.fromstring(hashAsString)))

					error(
						`Integrity check failed: hash check failed! computed {computedAsBase64} but got {hashAsBase64} from extension data [0-16]`,
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
