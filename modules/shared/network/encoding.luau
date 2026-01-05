--!strict

local MessagePack = require("@shared/msgpack")
local XXH32 = require("@shared/crypto/XXH32")

-- thank you rojo
local CFRAME_ID_LOOKUP_TABLE = table.freeze({
	[0x02] = CFrame.fromEulerAnglesYXZ(0, 0, 0),
	[0x03] = CFrame.fromEulerAnglesYXZ(math.rad(90), 0, 0),
	[0x05] = CFrame.fromEulerAnglesYXZ(0, math.rad(180), math.rad(180)),
	[0x06] = CFrame.fromEulerAnglesYXZ(math.rad(-90), 0, 0),
	[0x07] = CFrame.fromEulerAnglesYXZ(0, math.rad(180), math.rad(90)),
	[0x09] = CFrame.fromEulerAnglesYXZ(0, math.rad(90), math.rad(90)),
	[0x0a] = CFrame.fromEulerAnglesYXZ(0, 0, math.rad(90)),
	[0x0c] = CFrame.fromEulerAnglesYXZ(0, math.rad(-90), math.rad(90)),
	[0x0d] = CFrame.fromEulerAnglesYXZ(math.rad(-90), math.rad(-90), 0),
	[0x0e] = CFrame.fromEulerAnglesYXZ(math.rad(0), math.rad(-90), 0),
	[0x10] = CFrame.fromEulerAnglesYXZ(math.rad(90), math.rad(-90), 0),
	[0x11] = CFrame.fromEulerAnglesYXZ(math.rad(0), math.rad(90), 180),

	[0x14] = CFrame.fromEulerAnglesYXZ(0, math.rad(180), 0),
	[0x15] = CFrame.fromEulerAnglesYXZ(math.rad(-90), math.rad(-180), 0),
	[0x17] = CFrame.fromEulerAnglesYXZ(0, 0, math.rad(180)),
	[0x18] = CFrame.fromEulerAnglesYXZ(math.rad(90), math.rad(180), 0),
	[0x19] = CFrame.fromEulerAnglesYXZ(0, 0, math.rad(-90)),
	[0x1b] = CFrame.fromEulerAnglesYXZ(0, math.rad(-90), math.rad(-90)),
	[0x1c] = CFrame.fromEulerAnglesYXZ(0, math.rad(-180), math.rad(-90)),
	[0x1e] = CFrame.fromEulerAnglesYXZ(0, math.rad(90), math.rad(-90)),
	[0x1f] = CFrame.fromEulerAnglesYXZ(math.rad(90), math.rad(90), 0),
	[0x20] = CFrame.fromEulerAnglesYXZ(0, math.rad(90), 0),
	[0x22] = CFrame.fromEulerAnglesYXZ(math.rad(-90), math.rad(90), 0),
	[0x23] = CFrame.fromEulerAnglesYXZ(0, math.rad(-90), math.rad(180)),
})

type Pair<T> = {
	encode: (datatype: T) -> buffer,
	decode: (buf: buffer) -> T,
	type: number,
}

local BASIC_DATATYPE_TO_PAIR: { [string]: Pair<any> } = {
	CFrame = {
		encode = function(datatype: CFrame)
			local position = datatype.Position
			local rotation = datatype.Rotation

			local id
			for key, value in CFRAME_ID_LOOKUP_TABLE do
				if rotation == value then
					id = key
					break
				end
			end

			local buf = buffer.create(if id then 13 else 49)

			buffer.writeu8(buf, 0, id or 0)

			if id then
				buffer.writef32(buf, 1, position.X)
				buffer.writef32(buf, 5, position.Y)
				buffer.writef32(buf, 9, position.Z)
			else
				for index, component in { datatype:GetComponents() } do
					buffer.writef32(buf, ((index - 1) * 4) + 1, component)
				end
			end

			return buf
		end,

		decode = function(buf: buffer)
			local id = buffer.readu8(buf, 0)

			if id == 0 then
				local positionX, positionY, positionZ, xx, xy, xz, yx, yy, yz, zx, zy, zz =
					buffer.readf32(buf, 1),
					buffer.readf32(buf, 5),
					buffer.readf32(buf, 9),
					buffer.readf32(buf, 13),
					buffer.readf32(buf, 17),
					buffer.readf32(buf, 21),
					buffer.readf32(buf, 25),
					buffer.readf32(buf, 29),
					buffer.readf32(buf, 33),
					buffer.readf32(buf, 37),
					buffer.readf32(buf, 41),
					buffer.readf32(buf, 45)

				return CFrame.new(positionX, positionY, positionZ, xx, xy, xz, yx, yy, yz, zx, zy, zz)
			else
				local positionX, positionY, positionZ =
					buffer.readf32(buf, 1), buffer.readf32(buf, 4), buffer.readf32(buf, 8)

				return CFrame.new(positionX, positionY, positionZ) * CFRAME_ID_LOOKUP_TABLE[id]
			end
		end,

		type = 13,
	},

	Vector3 = {
		encode = function(datatype: Vector3)
			local buf = buffer.create(12)
			buffer.writef64(buf, 0, datatype.X)
			buffer.writef64(buf, 8, datatype.Y)
			buffer.writef64(buf, 16, datatype.Z)
			return buf
		end,

		decode = function(buf: buffer)
			return Vector3.new(buffer.readf64(buf, 0), buffer.readf64(buf, 8), buffer.readf64(buf, 16))
		end,

		type = 14,
	},
}

-- Instances are specially handled
local INSTANCE_EXTENSION_TYPE: number = 12 -- 0x0c

local TYPE_EXISTS: { [number]: string } = {
	[INSTANCE_EXTENSION_TYPE] = "Instance",
}

for index, pair in BASIC_DATATYPE_TO_PAIR do
	TYPE_EXISTS[pair.type] = index
end

table.freeze(TYPE_EXISTS)

local Module = {}

-- Returns a u32
local function computeDecentChecksum(instance: Instance): number
	-- We should only use datapoints here that are actually garuanteed to be shared with the server
	-- So something like :GetFullName() might seem ok, but it's return could actually differ on the client and server (as the client could change the instance's parent or name).
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

			table.insert(instanceArray, data :: Instance)
			index += 1

			data = extension
		else
			local pair = BASIC_DATATYPE_TO_PAIR[datatype]
			if pair then
				data = MessagePack.Extension.new(pair.type, pair.encode(data))
			end
		end

		return data, instanceArray
	end

	local dataWithoutInstances, instanceArray = encode(data, {}, true)
	return MessagePack.encode(dataWithoutInstances), instanceArray
end

-- Decodes a MessagePack blob with an instance array, returning the decoded data.
-- This function CAN and WILL error if given invalid data. Please wrap in a pcall.
function Module.decode(data: buffer, instanceArray: { Instance }): any
	local result = MessagePack.decode(data)

	local function decode(data: any)
		if typeof(data) == "table" then
			if data._msgpackType ~= nil and TYPE_EXISTS[data.type :: number] then
				if data.type == INSTANCE_EXTENSION_TYPE then
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
				else
					return BASIC_DATATYPE_TO_PAIR[TYPE_EXISTS[data.type :: number]].decode(data.data :: buffer)
				end
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
