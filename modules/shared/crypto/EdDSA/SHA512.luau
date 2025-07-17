--[=[
	Cryptography library: SHA512 (Optimized for EdDSA)
--]=]

--!strict
--!optimize 2
--!native

local FRONTK = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 
	0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 
	0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 
	0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece, 
	0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 
	0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 
	0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
}

local BACKK = {
	0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538,
	0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242, 0x45706fbe,
	0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235,
	0xcf692694, 0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
	0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab,
	0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725,
	0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed,
	0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
	0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218,
	0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53,
	0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373,
	0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
	0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b, 0xea26619c,
	0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6,
	0xbef90dae, 0x131c471b, 0x23047d84, 0x40c72493, 0x15c9bebc,
	0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
}

local BLOCK_FRONT = table.create(80)
local BLOCK_BACK = table.create(80)
local RESULT_BUFFER = buffer.create(64)

local function SHA512(Message: buffer, Salt: buffer?): buffer
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))
		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)
		Message = MessageWithSalt
	end

	local BackK, FrontK = BACKK, FRONTK
	local BlockFront, BlockBack = BLOCK_FRONT, BLOCK_BACK 

	local ContentLength = buffer.len(Message)
	local Padding = (128 - ((ContentLength + 17) % 128)) % 128
	local NewContentLength = ContentLength + 1 + Padding + 16
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Message)
	buffer.writeu8(NewContent, ContentLength, 0x80)

	local BaseOffset = ContentLength + 1 + Padding
	buffer.writeu8(NewContent, BaseOffset, 0)
	buffer.writeu8(NewContent, BaseOffset + 1, 0)
	buffer.writeu8(NewContent, BaseOffset + 2, 0)
	buffer.writeu8(NewContent, BaseOffset + 3, 0)
	buffer.writeu8(NewContent, BaseOffset + 4, 0)
	buffer.writeu8(NewContent, BaseOffset + 5, 0)
	buffer.writeu8(NewContent, BaseOffset + 6, 0)
	buffer.writeu8(NewContent, BaseOffset + 7, 0)

	local Length8 = ContentLength * 8
	buffer.writeu8(NewContent, BaseOffset + 15, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 14, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 13, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 12, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 11, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 10, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 9, Length8 % 256)
	Length8 = Length8 // 256
	buffer.writeu8(NewContent, BaseOffset + 8, Length8 % 256)

	local H1F, H2F, H3F, H4F = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local H5F, H6F, H7F, H8F = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local H1B, H2B, H3B, H4B = 0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1
	local H5B, H6B, H7B, H8B = 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179

	for Offset = 0, NewContentLength - 1, 128 do
		BlockFront[1] = bit32.byteswap(buffer.readu32(NewContent, Offset))
		BlockBack[1] = bit32.byteswap(buffer.readu32(NewContent, Offset + 4))
		BlockFront[2] = bit32.byteswap(buffer.readu32(NewContent, Offset + 8))
		BlockBack[2] = bit32.byteswap(buffer.readu32(NewContent, Offset + 12))
		BlockFront[3] = bit32.byteswap(buffer.readu32(NewContent, Offset + 16))
		BlockBack[3] = bit32.byteswap(buffer.readu32(NewContent, Offset + 20))
		BlockFront[4] = bit32.byteswap(buffer.readu32(NewContent, Offset + 24))
		BlockBack[4] = bit32.byteswap(buffer.readu32(NewContent, Offset + 28))
		BlockFront[5] = bit32.byteswap(buffer.readu32(NewContent, Offset + 32))
		BlockBack[5] = bit32.byteswap(buffer.readu32(NewContent, Offset + 36))
		BlockFront[6] = bit32.byteswap(buffer.readu32(NewContent, Offset + 40))
		BlockBack[6] = bit32.byteswap(buffer.readu32(NewContent, Offset + 44))
		BlockFront[7] = bit32.byteswap(buffer.readu32(NewContent, Offset + 48))
		BlockBack[7] = bit32.byteswap(buffer.readu32(NewContent, Offset + 52))
		BlockFront[8] = bit32.byteswap(buffer.readu32(NewContent, Offset + 56))
		BlockBack[8] = bit32.byteswap(buffer.readu32(NewContent, Offset + 60))
		BlockFront[9] = bit32.byteswap(buffer.readu32(NewContent, Offset + 64))
		BlockBack[9] = bit32.byteswap(buffer.readu32(NewContent, Offset + 68))
		BlockFront[10] = bit32.byteswap(buffer.readu32(NewContent, Offset + 72))
		BlockBack[10] = bit32.byteswap(buffer.readu32(NewContent, Offset + 76))
		BlockFront[11] = bit32.byteswap(buffer.readu32(NewContent, Offset + 80))
		BlockBack[11] = bit32.byteswap(buffer.readu32(NewContent, Offset + 84))
		BlockFront[12] = bit32.byteswap(buffer.readu32(NewContent, Offset + 88))
		BlockBack[12] = bit32.byteswap(buffer.readu32(NewContent, Offset + 92))
		BlockFront[13] = bit32.byteswap(buffer.readu32(NewContent, Offset + 96))
		BlockBack[13] = bit32.byteswap(buffer.readu32(NewContent, Offset + 100))
		BlockFront[14] = bit32.byteswap(buffer.readu32(NewContent, Offset + 104))
		BlockBack[14] = bit32.byteswap(buffer.readu32(NewContent, Offset + 108))
		BlockFront[15] = bit32.byteswap(buffer.readu32(NewContent, Offset + 112))
		BlockBack[15] = bit32.byteswap(buffer.readu32(NewContent, Offset + 116))
		BlockFront[16] = bit32.byteswap(buffer.readu32(NewContent, Offset + 120))
		BlockBack[16] = bit32.byteswap(buffer.readu32(NewContent, Offset + 124))

		for T = 17, 80 do
			local FT15, BT15 = BlockFront[T - 15], BlockBack[T - 15]
			local S0Front, S0Back = bit32.bxor(
				bit32.rshift(FT15, 1), bit32.lshift(BT15, 31), 
				bit32.rshift(FT15, 8), bit32.lshift(BT15, 24),
				bit32.rshift(FT15, 7)
			), bit32.bxor(
				bit32.rshift(BT15, 1), bit32.lshift(FT15, 31), 
				bit32.rshift(BT15, 8), bit32.lshift(FT15, 24),
				bit32.rshift(BT15, 7), bit32.lshift(FT15, 25)
			)

			local FT2, BT2 = BlockFront[T - 2], BlockBack[T - 2]
			local S1Front, S1Back = bit32.bxor(
				bit32.rshift(FT2, 19), bit32.lshift(BT2, 13),
				bit32.lshift(FT2, 3), bit32.rshift(BT2, 29),
				bit32.rshift(FT2, 6)
			), bit32.bxor(
				bit32.rshift(BT2, 19), bit32.lshift(FT2, 13),
				bit32.lshift(BT2, 3), bit32.rshift(FT2, 29),
				bit32.rshift(BT2, 6), bit32.lshift(FT2, 26)
			)

			local TempBack = BlockBack[T - 16] + S0Back + BlockBack[T - 7] + S1Back
			BlockBack[T] = bit32.bor(TempBack, 0)
			BlockFront[T] = BlockFront[T - 16] + S0Front + BlockFront[T - 7] + S1Front + TempBack // 4294967296
		end

		local AF, AB, BF, BB, CF, CB, DF, DB = H1F, H1B, H2F, H2B, H3F, H3B, H4F, H4B
		local EF, EB, FF, FB, GF, GB, HF, HB = H5F, H5B, H6F, H6B, H7F, H7B, H8F, H8B

		for T = 1, 80 do
			local S1Front, S1Back = bit32.bxor(
				bit32.rshift(EF, 14), bit32.lshift(EB, 18),
				bit32.rshift(EF, 18), bit32.lshift(EB, 14),
				bit32.lshift(EF, 23), bit32.rshift(EB, 9)
			), bit32.bxor(
				bit32.rshift(EB, 14), bit32.lshift(EF, 18),
				bit32.rshift(EB, 18), bit32.lshift(EF, 14),
				bit32.lshift(EB, 23), bit32.rshift(EF, 9)
			)
			local S0Front, S0Back = bit32.bxor(
				bit32.rshift(AF, 28), bit32.lshift(AB, 4),
				bit32.lshift(AF, 30), bit32.rshift(AB, 2),
				bit32.lshift(AF, 25), bit32.rshift(AB, 7)
			), bit32.bxor(
				bit32.rshift(AB, 28), bit32.lshift(AF, 4),
				bit32.lshift(AB, 30), bit32.rshift(AF, 2),
				bit32.lshift(AB, 25), bit32.rshift(AF, 7)
			)

			local ChBack = bit32.bxor(bit32.band(EB, FB), bit32.band(-1 - EB, GB))
			local ChFront = bit32.bxor(bit32.band(EF, FF), bit32.band(-1 - EF, GF))
			local MajBack = bit32.band(CB, BB) + bit32.band(AB, bit32.bxor(CB, BB))
			local MajFront = bit32.band(CF, BF) + bit32.band(AF, bit32.bxor(CF, BF))

			local Temp1Back = HB + S1Back + ChBack + BackK[T] + BlockBack[T]
			local Temp1Front = HF + S1Front + ChFront + FrontK[T] + BlockFront[T] + Temp1Back // 4294967296
			Temp1Back = bit32.bor(Temp1Back, 0)

			local Temp2Back = S0Back + MajBack
			local Temp2Front = S0Front + MajFront

			HF, HB = GF, GB
			GF, GB = FF, FB
			FF, FB = EF, EB

			EB = DB + Temp1Back
			EF = DF + Temp1Front + EB // 4294967296
			EB = bit32.bor(EB, 0)

			DF, DB = CF, CB
			CF, CB = BF, BB
			BF, BB = AF, AB

			AB = Temp1Back + Temp2Back
			AF = Temp1Front + Temp2Front + AB // 4294967296
			AB = bit32.bor(AB, 0)
		end

		H1B = H1B + AB
		H1F = bit32.bor(H1F + AF + H1B // 4294967296, 0)
		H1B = bit32.bor(H1B, 0)

		H2B = H2B + BB
		H2F = bit32.bor(H2F + BF + H2B // 4294967296, 0)
		H2B = bit32.bor(H2B, 0)

		H3B = H3B + CB
		H3F = bit32.bor(H3F + CF + H3B // 4294967296, 0)
		H3B = bit32.bor(H3B, 0)

		H4B = H4B + DB
		H4F = bit32.bor(H4F + DF + H4B // 4294967296, 0)
		H4B = bit32.bor(H4B, 0)

		H5B = H5B + EB
		H5F = bit32.bor(H5F + EF + H5B // 4294967296, 0)
		H5B = bit32.bor(H5B, 0)

		H6B = H6B + FB
		H6F = bit32.bor(H6F + FF + H6B // 4294967296, 0)
		H6B = bit32.bor(H6B, 0)

		H7B = H7B + GB
		H7F = bit32.bor(H7F + GF + H7B // 4294967296, 0)
		H7B = bit32.bor(H7B, 0)

		H8B = H8B + HB
		H8F = bit32.bor(H8F + HF + H8B // 4294967296, 0)
		H8B = bit32.bor(H8B, 0)
	end

	buffer.writeu32(RESULT_BUFFER, 0, bit32.byteswap(H1F))
	buffer.writeu32(RESULT_BUFFER, 4, bit32.byteswap(H1B))
	buffer.writeu32(RESULT_BUFFER, 8, bit32.byteswap(H2F))
	buffer.writeu32(RESULT_BUFFER, 12, bit32.byteswap(H2B))
	buffer.writeu32(RESULT_BUFFER, 16, bit32.byteswap(H3F))
	buffer.writeu32(RESULT_BUFFER, 20, bit32.byteswap(H3B))
	buffer.writeu32(RESULT_BUFFER, 24, bit32.byteswap(H4F))
	buffer.writeu32(RESULT_BUFFER, 28, bit32.byteswap(H4B))
	buffer.writeu32(RESULT_BUFFER, 32, bit32.byteswap(H5F))
	buffer.writeu32(RESULT_BUFFER, 36, bit32.byteswap(H5B))
	buffer.writeu32(RESULT_BUFFER, 40, bit32.byteswap(H6F))
	buffer.writeu32(RESULT_BUFFER, 44, bit32.byteswap(H6B))
	buffer.writeu32(RESULT_BUFFER, 48, bit32.byteswap(H7F))
	buffer.writeu32(RESULT_BUFFER, 52, bit32.byteswap(H7B))
	buffer.writeu32(RESULT_BUFFER, 56, bit32.byteswap(H8F))
	buffer.writeu32(RESULT_BUFFER, 60, bit32.byteswap(H8B))

	return RESULT_BUFFER
end

return SHA512