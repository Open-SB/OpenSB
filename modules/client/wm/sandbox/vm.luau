-- // Environment changes in the VM are not supposed to alter the behaviour of the VM so we localise globals beforehand
local type = type
local pcall = pcall
local error = error
local tonumber = tonumber
local assert = assert
local setmetatable = setmetatable
local getfenv = getfenv
local setfenv = setfenv

local string_format = string.format
local string_match = string.match
local string_sub = string.sub

local table_move = table.move
local table_pack = table.pack
local table_unpack = table.unpack
local table_create = table.create
local table_insert = table.insert
local table_freeze = table.freeze

local coroutine_create = coroutine.create
local coroutine_yield = coroutine.yield
local coroutine_resume = coroutine.resume
local coroutine_close = coroutine.close
local coroutine_running = coroutine.running

local buffer_fromstring = buffer.fromstring
local buffer_len = buffer.len
local buffer_readu8 = buffer.readu8
local buffer_readu32 = buffer.readu32
local buffer_readstring = buffer.readstring
local buffer_readf32 = buffer.readf32
local buffer_readf64 = buffer.readf64

local bit32_bor = bit32.bor
local bit32_band = bit32.band
local bit32_btest = bit32.btest
local bit32_rshift = bit32.rshift
local bit32_lshift = bit32.lshift
local bit32_extract = bit32.extract

local Vector3_new = Vector3.new

local debug_info = debug.info

local closureInfo = setmetatable({}, { __mode = "k" })
local running
local fmap

local ttisnumber = function(v)
	return type(v) == "number"
end
-- local ttisstring = function(v)
-- 	return type(v) == "string"
-- end
local ttisboolean = function(v)
	return type(v) == "boolean"
end
local ttisfunction = function(v)
	return type(v) == "function"
end

-- // opList contains information about the instruction, each instruction is defined in this format:
-- // {OP_NAME, OP_MODE, K_MODE, HAS_AUX}
-- // OP_MODE specifies what type of registers the instruction uses if any
--		0 = NONE
--		1 = A
--		2 = AB
--		3 = ABC
--		4 = AD
--		5 = AE
-- // K_MODE specifies if the instruction has a register that holds a constant table index, which will be directly converted to the constant in the 2nd pass
--		0 = NONE
--		1 = AUX
--		2 = C
--		3 = D
--		4 = AUX import
--		5 = AUX boolean low 1 bit
--		6 = AUX number low 24 bits
-- // HAS_AUX boolean specifies whether the instruction is followed up with an AUX word, which may be used to execute the instruction.

local opList = {
	{ "NOP", 0, 0, false },
	{ "BREAK", 0, 0, false },
	{ "LOADNIL", 1, 0, false },
	{ "LOADB", 3, 0, false },
	{ "LOADN", 4, 0, false },
	{ "LOADK", 4, 3, false },
	{ "MOVE", 2, 0, false },
	{ "GETGLOBAL", 1, 1, true },
	{ "SETGLOBAL", 1, 1, true },
	{ "GETUPVAL", 2, 0, false },
	{ "SETUPVAL", 2, 0, false },
	{ "CLOSEUPVALS", 1, 0, false },
	{ "GETIMPORT", 4, 4, true },
	{ "GETTABLE", 3, 0, false },
	{ "SETTABLE", 3, 0, false },
	{ "GETTABLEKS", 3, 1, true },
	{ "SETTABLEKS", 3, 1, true },
	{ "GETTABLEN", 3, 0, false },
	{ "SETTABLEN", 3, 0, false },
	{ "NEWCLOSURE", 4, 0, false },
	{ "NAMECALL", 3, 1, true },
	{ "CALL", 3, 0, false },
	{ "RETURN", 2, 0, false },
	{ "JUMP", 4, 0, false },
	{ "JUMPBACK", 4, 0, false },
	{ "JUMPIF", 4, 0, false },
	{ "JUMPIFNOT", 4, 0, false },
	{ "JUMPIFEQ", 4, 0, true },
	{ "JUMPIFLE", 4, 0, true },
	{ "JUMPIFLT", 4, 0, true },
	{ "JUMPIFNOTEQ", 4, 0, true },
	{ "JUMPIFNOTLE", 4, 0, true },
	{ "JUMPIFNOTLT", 4, 0, true },
	{ "ADD", 3, 0, false },
	{ "SUB", 3, 0, false },
	{ "MUL", 3, 0, false },
	{ "DIV", 3, 0, false },
	{ "MOD", 3, 0, false },
	{ "POW", 3, 0, false },
	{ "ADDK", 3, 2, false },
	{ "SUBK", 3, 2, false },
	{ "MULK", 3, 2, false },
	{ "DIVK", 3, 2, false },
	{ "MODK", 3, 2, false },
	{ "POWK", 3, 2, false },
	{ "AND", 3, 0, false },
	{ "OR", 3, 0, false },
	{ "ANDK", 3, 2, false },
	{ "ORK", 3, 2, false },
	{ "CONCAT", 3, 0, false },
	{ "NOT", 2, 0, false },
	{ "MINUS", 2, 0, false },
	{ "LENGTH", 2, 0, false },
	{ "NEWTABLE", 2, 0, true },
	{ "DUPTABLE", 4, 3, false },
	{ "SETLIST", 3, 0, true },
	{ "FORNPREP", 4, 0, false },
	{ "FORNLOOP", 4, 0, false },
	{ "FORGLOOP", 4, 8, true },
	{ "FORGPREP_INEXT", 4, 0, false },
	{ "FASTCALL3", 3, 1, true },
	{ "FORGPREP_NEXT", 4, 0, false },
	{ "DEP_FORGLOOP_NEXT", 0, 0, false },
	{ "GETVARARGS", 2, 0, false },
	{ "DUPCLOSURE", 4, 3, false },
	{ "PREPVARARGS", 1, 0, false },
	{ "LOADKX", 1, 1, true },
	{ "JUMPX", 5, 0, false },
	{ "FASTCALL", 3, 0, false },
	{ "COVERAGE", 5, 0, false },
	{ "CAPTURE", 2, 0, false },
	{ "SUBRK", 3, 7, false },
	{ "DIVRK", 3, 7, false },
	{ "FASTCALL1", 3, 0, false },
	{ "FASTCALL2", 3, 0, true },
	{ "FASTCALL2K", 3, 1, true },
	{ "FORGPREP", 4, 0, false },
	{ "JUMPXEQKNIL", 4, 5, true },
	{ "JUMPXEQKB", 4, 5, true },
	{ "JUMPXEQKN", 4, 6, true },
	{ "JUMPXEQKS", 4, 6, true },
	{ "IDIV", 3, 0, false },
	{ "IDIVK", 3, 2, false },
}

local LUA_MULTRET = -1
local LUA_GENERALIZED_TERMINATOR = -2

local function luau_deserialize(bytecode)
	local stream = if type(bytecode) == "string" then buffer_fromstring(bytecode) else bytecode
	local cursor = 0

	local function readByte()
		local byte = buffer_readu8(stream, cursor)
		cursor = cursor + 1
		return byte
	end

	local function readWord()
		local word = buffer_readu32(stream, cursor)
		cursor = cursor + 4
		return word
	end

	local function readFloat()
		local float = buffer_readf32(stream, cursor)
		cursor = cursor + 4
		return float
	end

	local function readDouble()
		local double = buffer_readf64(stream, cursor)
		cursor = cursor + 8
		return double
	end

	local function readVarInt()
		local result = 0

		for i = 0, 4 do
			local value = readByte()
			result = bit32_bor(result, bit32_lshift(bit32_band(value, 0x7F), i * 7))
			if not bit32_btest(value, 0x80) then
				break
			end
		end

		return result
	end

	local function readString()
		local size = readVarInt()

		if size == 0 then
			return ""
		else
			local str = buffer_readstring(stream, cursor, size)
			cursor = cursor + size

			return str
		end
	end

	local luauVersion = readByte()
	local typesVersion = 0
	if luauVersion == 0 then
		error("the provided bytecode is an error message", 0)
	elseif luauVersion < 3 or luauVersion > 6 then
		error("the version of the provided bytecode is unsupported", 0)
	elseif luauVersion >= 4 then
		typesVersion = readByte()
	end

	local stringCount = readVarInt()
	local stringList = table_create(stringCount)

	for i = 1, stringCount do
		stringList[i] = readString()
	end

	local function readInstruction(codeList)
		local value = readWord()
		local opcode = bit32_band(value, 0xFF)

		local opinfo = opList[opcode + 1]
		local opname = opinfo[1]
		local opmode = opinfo[2]
		local kmode = opinfo[3]
		local usesAux = opinfo[4]

		local inst = {
			opcode = opcode,
			opname = opname,
			opmode = opmode,
			kmode = kmode,
			usesAux = usesAux,
		}

		table_insert(codeList, inst)

		if opmode == 1 then --[[ A ]]
			inst.A = bit32_band(bit32_rshift(value, 8), 0xFF)
		elseif opmode == 2 then --[[ AB ]]
			inst.A = bit32_band(bit32_rshift(value, 8), 0xFF)
			inst.B = bit32_band(bit32_rshift(value, 16), 0xFF)
		elseif opmode == 3 then --[[ ABC ]]
			inst.A = bit32_band(bit32_rshift(value, 8), 0xFF)
			inst.B = bit32_band(bit32_rshift(value, 16), 0xFF)
			inst.C = bit32_band(bit32_rshift(value, 24), 0xFF)
		elseif opmode == 4 then --[[ AD ]]
			inst.A = bit32_band(bit32_rshift(value, 8), 0xFF)
			local temp = bit32_band(bit32_rshift(value, 16), 0xFFFF)
			inst.D = if temp < 0x8000 then temp else temp - 0x10000
		elseif opmode == 5 then --[[ AE ]]
			local temp = bit32_band(bit32_rshift(value, 8), 0xFFFFFF)
			inst.E = if temp < 0x800000 then temp else temp - 0x1000000
		end

		if usesAux then
			local aux = readWord()
			inst.aux = aux

			table_insert(codeList, { value = aux, opname = "auxvalue" })
		end

		return usesAux
	end

	local function checkkmode(inst, k)
		local kmode = inst.kmode

		if kmode == 1 then --// AUX
			inst.K = k[inst.aux + 1]
		elseif kmode == 2 then --// C
			inst.K = k[inst.C + 1]
		elseif kmode == 3 then --// D
			inst.K = k[inst.D + 1]
		elseif kmode == 4 then --// AUX import
			local extend = inst.aux
			local count = bit32_rshift(extend, 30)
			local id0 = bit32_band(bit32_rshift(extend, 20), 0x3FF)

			inst.K0 = k[id0 + 1]
			inst.KC = count
			if count == 2 then
				local id1 = bit32_band(bit32_rshift(extend, 10), 0x3FF)

				inst.K1 = k[id1 + 1]
			elseif count == 3 then
				local id1 = bit32_band(bit32_rshift(extend, 10), 0x3FF)
				local id2 = bit32_band(bit32_rshift(extend, 0), 0x3FF)

				inst.K1 = k[id1 + 1]
				inst.K2 = k[id2 + 1]
			end
		elseif kmode == 5 then --// AUX boolean low 1 bit
			inst.K = bit32_extract(inst.aux, 0, 1) == 1
			inst.KN = bit32_extract(inst.aux, 31, 1) == 1
		elseif kmode == 6 then --// AUX number low 24 bits
			inst.K = k[bit32_extract(inst.aux, 0, 24) + 1]
			inst.KN = bit32_extract(inst.aux, 31, 1) == 1
		elseif kmode == 7 then --// B
			inst.K = k[inst.B + 1]
		elseif kmode == 8 then --// AUX number low 16 bits
			inst.K = bit32_band(inst.aux, 0xf)
		end
	end

	local function readProto(bytecodeid)
		local maxstacksize = readByte()
		local numparams = readByte()
		local nups = readByte()
		local isvararg = readByte() ~= 0

		if luauVersion >= 4 then
			readByte() --// flags
			local typesize = readVarInt()
			cursor = cursor + typesize
		end

		local sizecode = readVarInt()
		local codelist = table_create(sizecode)

		local skipnext = false
		for _ = 1, sizecode do
			if skipnext then
				skipnext = false
				continue
			end

			skipnext = readInstruction(codelist)
		end

		local sizek = readVarInt()
		local klist = table_create(sizek)

		for i = 1, sizek do
			local kt = readByte()
			local k

			if kt == 0 then --// Nil
				k = nil
			elseif kt == 1 then --// Bool
				k = readByte() ~= 0
			elseif kt == 2 then --// Number
				k = readDouble()
			elseif kt == 3 then --// String
				k = stringList[readVarInt()]
			elseif kt == 4 then --// Import
				k = readWord()
			elseif kt == 5 then --// Table
				local dataLength = readVarInt()
				k = table_create(dataLength)

				-- selene: allow(shadowing)
				for i = 1, dataLength do
					k[i] = readVarInt()
				end
			elseif kt == 6 then --// Closure
				k = readVarInt()
			elseif kt == 7 then --// Vector
				local x, y, z, _ = readFloat(), readFloat(), readFloat(), readFloat()

				k = Vector3_new(x, y, z)
			end

			klist[i] = k
		end

		-- // 2nd pass to replace constant references in the instruction
		for i = 1, sizecode do
			checkkmode(codelist[i], klist)
		end

		local sizep = readVarInt()
		local protolist = table_create(sizep)

		for i = 1, sizep do
			protolist[i] = readVarInt() + 1
		end

		local linedefined = readVarInt()

		local debugnameindex = readVarInt()
		local debugname

		if debugnameindex ~= 0 then
			debugname = stringList[debugnameindex]
		end

		-- // lineinfo
		local lineinfoenabled = readByte() ~= 0
		local instructionlineinfo = nil

		if lineinfoenabled then
			local linegaplog2 = readByte()

			local intervals = bit32_rshift((sizecode - 1), linegaplog2) + 1

			local lineinfo = table_create(sizecode)
			local abslineinfo = table_create(intervals)

			local lastoffset = 0
			for j = 1, sizecode do
				lastoffset += readByte()
				lineinfo[j] = lastoffset
			end

			local lastline = 0
			for j = 1, intervals do
				lastline += readWord()
				abslineinfo[j] = lastline % (2 ^ 32)
			end

			instructionlineinfo = table_create(sizecode)

			for i = 1, sizecode do
				--// p->abslineinfo[pc >> p->linegaplog2] + p->lineinfo[pc];
				table_insert(instructionlineinfo, abslineinfo[bit32_rshift(i - 1, linegaplog2) + 1] + lineinfo[i])
			end
		end

		-- // debuginfo
		if readByte() ~= 0 then
			local sizel = readVarInt()
			for _ = 1, sizel do
				readVarInt()
				readVarInt()
				readVarInt()
				readByte()
			end
			local sizeupvalues = readVarInt()
			for _ = 1, sizeupvalues do
				readVarInt()
			end
		end

		return {
			maxstacksize = maxstacksize,
			numparams = numparams,
			nups = nups,
			isvararg = isvararg,
			linedefined = linedefined,
			debugname = debugname,

			sizecode = sizecode,
			code = codelist,

			sizek = sizek,
			k = klist,

			sizep = sizep,
			protos = protolist,

			lineinfoenabled = lineinfoenabled,
			instructionlineinfo = instructionlineinfo,

			bytecodeid = bytecodeid,
		}
	end

	-- userdataRemapping (not used in VM, left unused)
	if typesVersion == 3 then
		local index = readByte()

		while index ~= 0 do
			readVarInt()

			index = readByte()
		end
	end

	local protoCount = readVarInt()
	local protoList = table_create(protoCount)

	for i = 1, protoCount do
		protoList[i] = readProto(i - 1)
	end

	local mainProto = protoList[readVarInt() + 1]

	assert(cursor == buffer_len(stream), "deserializer cursor position mismatch")

	return {
		stringList = stringList,
		protoList = protoList,

		mainProto = mainProto,

		typesVersion = typesVersion,
	}
end

local vmStart = debug_info(function() end, "l")
local function luau_load(module, sandbox)
	if type(module) ~= "table" then
		module = luau_deserialize(module)
	end

	local env = sandbox.Environment

	local protolist = module.protoList
	local mainProto = module.mainProto

	local alive = true

	local function luau_close()
		alive = false
	end

	-- selene: allow(shadowing)
	local function luau_wrapclosure(module, proto, upvals, _env)
		local info = { proto = proto, sandbox = sandbox }

		-- TODO: @native
		local function luau_execute(...)
			local runningInfo = { thread = coroutine_running(), pc = 0, closureInfo = info }
			info.running = runningInfo

			local current = runningInfo
			local level = 2
			while true do
				local func = debug_info(level, "f")
				if not func then
					break
				end

				local cInfo = closureInfo[func]
				if cInfo then
					current.stackParent = cInfo.running

					break
				end

				level += 1
			end

			local passed = table_pack(...)
			local stack = table_create(proto.maxstacksize)
			local varargs = {
				len = 0,
				list = {},
			}

			table_move(passed, 1, proto.numparams, 0, stack)

			if proto.numparams < passed.n then
				local start = proto.numparams + 1
				local len = passed.n - proto.numparams
				varargs.len = len
				table_move(passed, start, start + len - 1, 1, varargs.list)
			end

			passed = nil

			local protos = proto.protos
			local code = proto.code

			local top, pc, open_upvalues, generalized_iterators =
				-1, 1, setmetatable({}, { __mode = "vs" }), setmetatable({}, { __mode = "ks" })
			local constants = proto.k

			local inst, op
			while alive do
				inst = code[pc]
				op = inst.opcode

				running = runningInfo
				runningInfo.pc = pc

				pc += 1

				-- selene: allow(empty_if)
				if op == 0 then --[[ NOP ]]
					--// Do nothing
				elseif op == 1 then --[[ BREAK ]]
					--[[ Skipped ]]
				elseif op == 2 then --[[ LOADNIL ]]
					stack[inst.A] = nil
				elseif op == 3 then --[[ LOADB ]]
					stack[inst.A] = inst.B == 1
					pc += inst.C
				elseif op == 4 then --[[ LOADN ]]
					stack[inst.A] = inst.D
				elseif op == 5 then --[[ LOADK ]]
					stack[inst.A] = inst.K
				elseif op == 6 then --[[ MOVE ]]
					stack[inst.A] = stack[inst.B]
				elseif op == 7 then --[[ GETGLOBAL ]]
					stack[inst.A] = getfenv()[inst.K]

					pc += 1 --// adjust for aux
				elseif op == 8 then --[[ SETGLOBAL ]]
					getfenv()[inst.K] = stack[inst.A]

					pc += 1 --// adjust for aux
				elseif op == 9 then --[[ GETUPVAL ]]
					local uv = upvals[inst.B + 1]
					stack[inst.A] = uv.store[uv.index]
				elseif op == 10 then --[[ SETUPVAL ]]
					local uv = upvals[inst.B + 1]
					uv.store[uv.index] = stack[inst.A]
				elseif op == 11 then --[[ CLOSEUPVALS ]]
					for i, uv in open_upvalues do
						if uv.index >= inst.A then
							uv.value = uv.store[uv.index]
							uv.store = uv
							uv.index = "value" --// self reference
							open_upvalues[i] = nil
						end
					end
				elseif op == 12 then --[[ GETIMPORT ]]
					local count = inst.KC
					local import = getfenv()[inst.K0]
					if count == 1 then
						stack[inst.A] = import
					elseif count == 2 then
						stack[inst.A] = import[inst.K1]
					elseif count == 3 then
						stack[inst.A] = import[inst.K1][inst.K2]
					end

					pc += 1 --// adjust for aux
				elseif op == 13 then --[[ GETTABLE ]]
					stack[inst.A] = stack[inst.B][stack[inst.C]]
				elseif op == 14 then --[[ SETTABLE ]]
					stack[inst.B][stack[inst.C]] = stack[inst.A]
				elseif op == 15 then --[[ GETTABLEKS ]]
					stack[inst.A] = stack[inst.B][inst.K]

					pc += 1 --// adjust for aux
				elseif op == 16 then --[[ SETTABLEKS ]]
					stack[inst.B][inst.K] = stack[inst.A]

					pc += 1 --// adjust for aux
				elseif op == 17 then --[[ GETTABLEN ]]
					stack[inst.A] = stack[inst.B][inst.C + 1]
				elseif op == 18 then --[[ SETTABLEN ]]
					stack[inst.B][inst.C + 1] = stack[inst.A]
				elseif op == 19 then --[[ NEWCLOSURE ]]
					local newPrototype = protolist[protos[inst.D + 1]]

					local nups = newPrototype.nups
					local upvalues = table_create(nups)
					stack[inst.A] = luau_wrapclosure(module, newPrototype, upvalues, getfenv())

					for i = 1, nups do
						local pseudo = code[pc]

						pc += 1

						local type = pseudo.A

						if type == 0 then --// value
							local upvalue = {
								value = stack[pseudo.B],
								index = "value", --// self reference
							}
							upvalue.store = upvalue

							upvalues[i] = upvalue
						elseif type == 1 then --// reference
							local index = pseudo.B
							local prev = open_upvalues[index]

							if prev == nil then
								prev = {
									index = index,
									store = stack,
								}
								open_upvalues[index] = prev
							end

							upvalues[i] = prev
						elseif type == 2 then --// upvalue
							upvalues[i] = upvals[pseudo.B + 1]
						end
					end
				elseif op == 20 then --[[ NAMECALL ]]
					local A = inst.A
					local sb = stack[inst.B]

					stack[A + 1] = sb

					pc += 1 --// adjust for aux

					stack[A] = sb[inst.K]
				elseif op == 21 then --[[ CALL ]]
					local A, B, C = inst.A, inst.B, inst.C

					local func = stack[A]
					local ret_list = table_pack(
						(fmap[func] or func)(table_unpack(stack, A + 1, A + if B == 0 then top - A else (B - 1)))
					)

					local ret_num
					if C == 0 then
						ret_num = ret_list.n
						top = A + ret_num - 1
					else
						ret_num = C - 1
					end

					table_move(ret_list, 1, ret_num, A, stack)
				elseif op == 22 then --[[ RETURN ]]
					local A = inst.A
					local B = inst.B

					return table_unpack(stack, A, A + if B - 1 == LUA_MULTRET then top - A else (B - 2))
				elseif op == 23 then --[[ JUMP ]]
					pc += inst.D
				elseif op == 24 then --[[ JUMPBACK ]]
					-- selene: allow(if_same_then_else)
					pc += inst.D
				elseif op == 25 then --[[ JUMPIF ]]
					if stack[inst.A] then
						pc += inst.D
					end
				elseif op == 26 then --[[ JUMPIFNOT ]]
					if not stack[inst.A] then
						pc += inst.D
					end
				elseif op == 27 then --[[ JUMPIFEQ ]]
					if stack[inst.A] == stack[inst.aux] then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 28 then --[[ JUMPIFLE ]]
					if stack[inst.A] <= stack[inst.aux] then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 29 then --[[ JUMPIFLT ]]
					if stack[inst.A] < stack[inst.aux] then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 30 then --[[ JUMPIFNOTEQ ]]
					if stack[inst.A] == stack[inst.aux] then
						pc += 1
					else
						pc += inst.D
					end
				elseif op == 31 then --[[ JUMPIFNOTLE ]]
					if stack[inst.A] <= stack[inst.aux] then
						pc += 1
					else
						pc += inst.D
					end
				elseif op == 32 then --[[ JUMPIFNOTLT ]]
					if stack[inst.A] < stack[inst.aux] then
						pc += 1
					else
						pc += inst.D
					end
				elseif op == 33 then --[[ ADD ]]
					stack[inst.A] = stack[inst.B] + stack[inst.C]
				elseif op == 34 then --[[ SUB ]]
					stack[inst.A] = stack[inst.B] - stack[inst.C]
				elseif op == 35 then --[[ MUL ]]
					stack[inst.A] = stack[inst.B] * stack[inst.C]
				elseif op == 36 then --[[ DIV ]]
					stack[inst.A] = stack[inst.B] / stack[inst.C]
				elseif op == 37 then --[[ MOD ]]
					stack[inst.A] = stack[inst.B] % stack[inst.C]
				elseif op == 38 then --[[ POW ]]
					stack[inst.A] = stack[inst.B] ^ stack[inst.C]
				elseif op == 39 then --[[ ADDK ]]
					stack[inst.A] = stack[inst.B] + inst.K
				elseif op == 40 then --[[ SUBK ]]
					stack[inst.A] = stack[inst.B] - inst.K
				elseif op == 41 then --[[ MULK ]]
					stack[inst.A] = stack[inst.B] * inst.K
				elseif op == 42 then --[[ DIVK ]]
					stack[inst.A] = stack[inst.B] / inst.K
				elseif op == 43 then --[[ MODK ]]
					stack[inst.A] = stack[inst.B] % inst.K
				elseif op == 44 then --[[ POWK ]]
					stack[inst.A] = stack[inst.B] ^ inst.K
				elseif op == 45 then --[[ AND ]]
					local value = stack[inst.B]
					stack[inst.A] = if value then stack[inst.C] or false else value
				elseif op == 46 then --[[ OR ]]
					local value = stack[inst.B]
					stack[inst.A] = if value then value else stack[inst.C] or false
				elseif op == 47 then --[[ ANDK ]]
					local value = stack[inst.B]
					stack[inst.A] = if value then inst.K or false else value
				elseif op == 48 then --[[ ORK ]]
					local value = stack[inst.B]
					stack[inst.A] = if value then value else inst.K or false
				elseif op == 49 then --[[ CONCAT ]]
					local s = ""
					for i = inst.B, inst.C do
						s ..= stack[i]
					end
					stack[inst.A] = s
				elseif op == 50 then --[[ NOT ]]
					stack[inst.A] = not stack[inst.B]
				elseif op == 51 then --[[ MINUS ]]
					stack[inst.A] = -stack[inst.B]
				elseif op == 52 then --[[ LENGTH ]]
					stack[inst.A] = #stack[inst.B]
				elseif op == 53 then --[[ NEWTABLE ]]
					stack[inst.A] = table_create(inst.aux)

					pc += 1 --// adjust for aux
				elseif op == 54 then --[[ DUPTABLE ]]
					local serialized = {}
					for _, id in inst.K do
						serialized[constants[id + 1]] = nil
					end
					stack[inst.A] = serialized
				elseif op == 55 then --[[ SETLIST ]]
					local B = inst.B
					local C = inst.C

					table_move(stack, B, B + if C - 1 == LUA_MULTRET then top - B else (C - 2), inst.aux, stack[inst.A])

					pc += 1 --// adjust for aux
				elseif op == 56 then --[[ FORNPREP ]]
					local A = inst.A

					local limit = stack[A]
					if not ttisnumber(limit) then
						local number = tonumber(limit)

						if number == nil then
							error("invalid 'for' limit (number expected)")
						end

						stack[A] = number
						limit = number
					end

					local step = stack[A + 1]
					if not ttisnumber(step) then
						local number = tonumber(step)

						if number == nil then
							error("invalid 'for' step (number expected)")
						end

						stack[A + 1] = number
						step = number
					end

					local index = stack[A + 2]
					if not ttisnumber(index) then
						local number = tonumber(index)

						if number == nil then
							error("invalid 'for' index (number expected)")
						end

						stack[A + 2] = number
						index = number
					end

					if step > 0 then
						if not (index <= limit) then
							pc += inst.D
						end
					else
						if not (limit <= index) then
							pc += inst.D
						end
					end
				elseif op == 57 then --[[ FORNLOOP ]]
					local A = inst.A
					local step = stack[A + 1]
					local index = stack[A + 2] + step

					stack[A + 2] = index

					if step > 0 then
						if index <= stack[A] then
							pc += inst.D
						end
					else
						if stack[A] <= index then
							pc += inst.D
						end
					end
				elseif op == 58 then --[[ FORGLOOP ]]
					local A = inst.A

					top = A + 6

					local it = stack[A]

					if ttisfunction(it) then
						local vals = { it(stack[A + 1], stack[A + 2]) }
						table_move(vals, 1, inst.K, A + 3, stack)

						if stack[A + 3] ~= nil then
							stack[A + 2] = stack[A + 3]
							pc += inst.D
						else
							pc += 1
						end
					else
						local ok, vals = coroutine_resume(generalized_iterators[inst], it, stack[A + 1], stack[A + 2])
						if not ok then
							error(vals)
						end
						if vals == LUA_GENERALIZED_TERMINATOR then
							generalized_iterators[inst] = nil
							pc += 1
						else
							table_move(vals, 1, inst.K, A + 3, stack)

							stack[A + 2] = stack[A + 3]
							pc += inst.D
						end
					end
				elseif op == 59 then --[[ FORGPREP_INEXT ]]
					if not ttisfunction(stack[inst.A]) then
						error(string_format("attempt to iterate over a %s value", type(stack[inst.A]))) -- FORGPREP_INEXT encountered non-function value
					end

					pc += inst.D
				elseif op == 60 then --[[ FASTCALL3 ]]
					--[[ Skipped ]]
					pc += 1 --// adjust for aux
				elseif op == 61 then --[[ FORGPREP_NEXT ]]
					-- selene: allow(if_same_then_else)
					if not ttisfunction(stack[inst.A]) then
						error(string_format("attempt to iterate over a %s value", type(stack[inst.A]))) -- FORGPREP_NEXT encountered non-function value
					end

					pc += inst.D
				elseif op == 63 then --[[ GETVARARGS ]]
					local b = inst.B - 1
					if b == LUA_MULTRET then
						local A = inst.A

						b = varargs.len
						top = A + b - 1

						table_move(varargs.list, 1, b, A, stack)
					else
						table_move(varargs.list, 1, b, inst.A, stack)
					end
				elseif op == 64 then --[[ DUPCLOSURE ]]
					local newPrototype = protolist[inst.K + 1] --// correct behavior would be to reuse the prototype if possible but it would not be useful here

					local nups = newPrototype.nups
					local upvalues = table_create(nups)
					stack[inst.A] = luau_wrapclosure(module, newPrototype, upvalues, getfenv())

					for i = 1, nups do
						local pseudo = code[pc]
						pc += 1

						local type = pseudo.A
						if type == 0 then --// value
							local upvalue = {
								value = stack[pseudo.B],
								index = "value", --// self reference
							}
							upvalue.store = upvalue

							upvalues[i] = upvalue

							--// references dont get handled by DUPCLOSURE
						elseif type == 2 then --// upvalue
							upvalues[i] = upvals[pseudo.B + 1]
						end
					end
				elseif op == 65 then --[[ PREPVARARGS ]]
					--[[ Handled by wrapper ]]
				elseif op == 66 then --[[ LOADKX ]]
					stack[inst.A] = inst.K

					pc += 1 --// adjust for aux
				elseif op == 67 then --[[ JUMPX ]]
					pc += inst.E
				elseif op == 68 then --[[ FASTCALL ]]
					--[[ Skipped ]]
				elseif op == 69 then --[[ COVERAGE ]]
					inst.E += 1
				elseif op == 70 then --[[ CAPTURE ]]
					--[[ Handled by CLOSURE ]]
					error("encountered unhandled CAPTURE")
				elseif op == 71 then --[[ SUBRK ]]
					stack[inst.A] = inst.K - stack[inst.C]
				elseif op == 72 then --[[ DIVRK ]]
					stack[inst.A] = inst.K / stack[inst.C]
				elseif op == 73 then --[[ FASTCALL1 ]]
					--[[ Skipped ]]
				elseif op == 74 then --[[ FASTCALL2 ]]
					--[[ Skipped ]]
					-- selene: allow(if_same_then_else)
					pc += 1 --// adjust for aux
				elseif op == 75 then --[[ FASTCALL2K ]]
					--[[ Skipped ]]
					-- selene: allow(if_same_then_else)
					pc += 1 --// adjust for aux
				elseif op == 76 then --[[ FORGPREP ]]
					local iterator = stack[inst.A]

					if not ttisfunction(iterator) then
						local loopInstruction = code[pc + inst.D]
						if generalized_iterators[loopInstruction] == nil then
							local function gen_iterator(...)
								for
									r1,
									r2,
									r3,
									r4,
									r5,
									r6,
									r7,
									r8,
									r9,
									r10,
									r11,
									r12,
									r13,
									r14,
									r15,
									r16,
									r17,
									r18,
									r19,
									r20,
									r21,
									r22,
									r23,
									r24,
									r25,
									r26,
									r27,
									r28,
									r29,
									r30,
									r31,
									r32,
									r33,
									r34,
									r35,
									r36,
									r37,
									r38,
									r39,
									r40,
									r41,
									r42,
									r43,
									r44,
									r45,
									r46,
									r47,
									r48,
									r49,
									r50,
									r51,
									r52,
									r53,
									r54,
									r55,
									r56,
									r57,
									r58,
									r59,
									r60,
									r61,
									r62,
									r63,
									r64,
									r65,
									r66,
									r67,
									r68,
									r69,
									r70,
									r71,
									r72,
									r73,
									r74,
									r75,
									r76,
									r77,
									r78,
									r79,
									r80,
									r81,
									r82,
									r83,
									r84,
									r85,
									r86,
									r87,
									r88,
									r89,
									r90,
									r91,
									r92,
									r93,
									r94,
									r95,
									r96,
									r97,
									r98,
									r99,
									r100,
									r101,
									r102,
									r103,
									r104,
									r105,
									r106,
									r107,
									r108,
									r109,
									r110,
									r111,
									r112,
									r113,
									r114,
									r115,
									r116,
									r117,
									r118,
									r119,
									r120,
									r121,
									r122,
									r123,
									r124,
									r125,
									r126,
									r127,
									r128,
									r129,
									r130,
									r131,
									r132,
									r133,
									r134,
									r135,
									r136,
									r137,
									r138,
									r139,
									r140,
									r141,
									r142,
									r143,
									r144,
									r145,
									r146,
									r147,
									r148,
									r149,
									r150,
									r151,
									r152,
									r153,
									r154,
									r155,
									r156,
									r157,
									r158,
									r159,
									r160,
									r161,
									r162,
									r163,
									r164,
									r165,
									r166,
									r167,
									r168,
									r169,
									r170,
									r171,
									r172,
									r173,
									r174,
									r175,
									r176,
									r177,
									r178,
									r179,
									r180,
									r181,
									r182,
									r183,
									r184,
									r185,
									r186,
									r187,
									r188,
									r189,
									r190,
									r191,
									r192,
									r193,
									r194,
									r195,
									r196,
									r197,
									r198,
									r199,
									r200
								in ... do
									coroutine_yield({
										r1,
										r2,
										r3,
										r4,
										r5,
										r6,
										r7,
										r8,
										r9,
										r10,
										r11,
										r12,
										r13,
										r14,
										r15,
										r16,
										r17,
										r18,
										r19,
										r20,
										r21,
										r22,
										r23,
										r24,
										r25,
										r26,
										r27,
										r28,
										r29,
										r30,
										r31,
										r32,
										r33,
										r34,
										r35,
										r36,
										r37,
										r38,
										r39,
										r40,
										r41,
										r42,
										r43,
										r44,
										r45,
										r46,
										r47,
										r48,
										r49,
										r50,
										r51,
										r52,
										r53,
										r54,
										r55,
										r56,
										r57,
										r58,
										r59,
										r60,
										r61,
										r62,
										r63,
										r64,
										r65,
										r66,
										r67,
										r68,
										r69,
										r70,
										r71,
										r72,
										r73,
										r74,
										r75,
										r76,
										r77,
										r78,
										r79,
										r80,
										r81,
										r82,
										r83,
										r84,
										r85,
										r86,
										r87,
										r88,
										r89,
										r90,
										r91,
										r92,
										r93,
										r94,
										r95,
										r96,
										r97,
										r98,
										r99,
										r100,
										r101,
										r102,
										r103,
										r104,
										r105,
										r106,
										r107,
										r108,
										r109,
										r110,
										r111,
										r112,
										r113,
										r114,
										r115,
										r116,
										r117,
										r118,
										r119,
										r120,
										r121,
										r122,
										r123,
										r124,
										r125,
										r126,
										r127,
										r128,
										r129,
										r130,
										r131,
										r132,
										r133,
										r134,
										r135,
										r136,
										r137,
										r138,
										r139,
										r140,
										r141,
										r142,
										r143,
										r144,
										r145,
										r146,
										r147,
										r148,
										r149,
										r150,
										r151,
										r152,
										r153,
										r154,
										r155,
										r156,
										r157,
										r158,
										r159,
										r160,
										r161,
										r162,
										r163,
										r164,
										r165,
										r166,
										r167,
										r168,
										r169,
										r170,
										r171,
										r172,
										r173,
										r174,
										r175,
										r176,
										r177,
										r178,
										r179,
										r180,
										r181,
										r182,
										r183,
										r184,
										r185,
										r186,
										r187,
										r188,
										r189,
										r190,
										r191,
										r192,
										r193,
										r194,
										r195,
										r196,
										r197,
										r198,
										r199,
										r200,
									})
								end

								coroutine_yield(LUA_GENERALIZED_TERMINATOR)
							end

							generalized_iterators[loopInstruction] = coroutine_create(gen_iterator)
						end
					end

					pc += inst.D
				elseif op == 77 then --[[ JUMPXEQKNIL ]]
					if (stack[inst.A] == nil) ~= inst.KN then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 78 then --[[ JUMPXEQKB ]]
					local ra = stack[inst.A]

					if (ttisboolean(ra) and (ra == inst.K)) ~= inst.KN then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 79 then --[[ JUMPXEQKN ]]
					local ra = stack[inst.A]

					if (ra == inst.K) ~= inst.KN then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 80 then --[[ JUMPXEQKS ]]
					-- selene: allow(if_same_then_else)
					local ra = stack[inst.A]

					if (ra == inst.K) ~= inst.KN then
						pc += inst.D
					else
						pc += 1
					end
				elseif op == 81 then --[[ IDIV ]]
					stack[inst.A] = stack[inst.B] // stack[inst.C]
				elseif op == 82 then --[[ IDIVK ]]
					stack[inst.A] = stack[inst.B] // inst.K
				else
					error("Unsupported Opcode: " .. inst.opname .. " op: " .. op)
				end
			end

			for i, uv in open_upvalues do
				uv.value = uv.store[uv.index]
				uv.store = uv
				uv.index = "value" --// self reference
				open_upvalues[i] = nil
			end

			for i, iter in generalized_iterators do
				coroutine_close(iter)
				generalized_iterators[i] = nil
			end
		end

		closureInfo[luau_execute] = info
		return setfenv(luau_execute, _env or env)
	end

	return luau_wrapclosure(module, mainProto), luau_close
end
local vmEnd = debug_info(function() end, "l")

local function getDebugInfo(runningInfo: table): (string, number?, string?)
	local closure = runningInfo.closureInfo
	local proto = closure.proto

	local source = closure.sandbox.StackSource or "(?)"
	local line = if proto.instructionlineinfo then proto.instructionlineinfo[runningInfo.pc] else nil
	local func = proto.debugname

	return source, line, func
end

local wmSource = debug_info(function() end, "s")
local function formatError(runningInfo: table, message: string): string
	if string_sub(message, 1, #wmSource) ~= wmSource then -- Level 0 error
		return message
	end

	local errorMessage = string_match(message, "^:%d+: (.+)$", #wmSource + 1)
	local source, line = getDebugInfo(runningInfo)

	return `{source}:{line}: {errorMessage}`
end

return table_freeze({
	luau_deserialize = luau_deserialize,
	luau_load = luau_load,

	setSandbox = function(sandbox)
		if fmap then
			return error("already initialized", 0)
		end

		fmap = sandbox.FunctionMap
	end,
	closureInfo = closureInfo,
	getRunning = function()
		return running
	end,

	getDebugInfo = getDebugInfo,
	formatError = formatError,

	vmStart = vmStart,
	vmEnd = vmEnd,
})
