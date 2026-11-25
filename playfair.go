package main

// FairPlay "playfair" key decryption, ported to Go from the protocol
// reference implementation (UxPlay's playfair/omg_hax, GPL — read for the
// algorithm; this is an original Go implementation of that algorithm).
//
// playfairDecrypt takes the 164-byte FairPlay handshake message (keymsg)
// and the 72-byte encrypted key (ekey) from the RTSP SETUP request and
// returns the 16-byte AES key used for the audio stream.
//
// All 32-bit word accesses on byte arrays are little-endian, matching the
// C code's uint32_t* casts on x86.

import (
	"encoding/binary"
	"math/bits"
)

// playfairDecrypt decrypts the AirPlay stream key.
// keymsg: 164-byte FairPlay handshake message; ekey: 72-byte encrypted key.
func playfairDecrypt(keymsg []byte, ekey []byte) []byte {
	chunk1 := ekey[16:32]
	chunk2 := ekey[56:72]

	sapKey := generateSessionKey(defaultSap, keymsg)

	var keySchedule [11][4]uint32
	generateKeySchedule(sapKey, &keySchedule)

	blockIn := make([]byte, 16)
	zXor(chunk2, blockIn, 1)
	cycle(blockIn, &keySchedule)

	keyOut := make([]byte, 16)
	for i := 0; i < 16; i++ {
		keyOut[i] = blockIn[i] ^ chunk1[i]
	}
	xXor(keyOut, keyOut, 1)
	zXor(keyOut, keyOut, 1)
	return keyOut
}

func xorBlocks(a, b, out []byte) {
	for i := 0; i < 16; i++ {
		out[i] = a[i] ^ b[i]
	}
}

func zXor(in, out []byte, blocks int) {
	for j := 0; j < blocks; j++ {
		for i := 0; i < 16; i++ {
			out[j*16+i] = in[j*16+i] ^ zKey[i]
		}
	}
}

func xXor(in, out []byte, blocks int) {
	for j := 0; j < blocks; j++ {
		for i := 0; i < 16; i++ {
			out[j*16+i] = in[j*16+i] ^ xKey[i]
		}
	}
}

func tXor(in, out []byte) {
	for i := 0; i < 16; i++ {
		out[i] = in[i] ^ tKey[i]
	}
}

// tableIndex returns the 256-byte sub-table of tableS1 for step i.
func tableIndex(i int) []byte {
	off := ((31 * i) % 0x28) << 8
	return tableS1[off : off+256]
}

// messageTableIndex returns the 256-byte sub-table of tableS2 for step i.
func messageTableIndex(i int) []byte {
	off := (97 * i % 144) << 8
	return tableS2[off : off+256]
}

// permuteTable2 returns the 256-byte sub-table of tableS4 for step i.
func permuteTable2(i int) []byte {
	off := ((71 * i) % 144) << 8
	return tableS4[off : off+256]
}

func permuteBlock1(block []byte) {
	block[0] = tableS3[block[0]]
	block[4] = tableS3[0x400+int(block[4])]
	block[8] = tableS3[0x800+int(block[8])]
	block[12] = tableS3[0xc00+int(block[12])]

	tmp := block[13]
	block[13] = tableS3[0x100+int(block[9])]
	block[9] = tableS3[0xd00+int(block[5])]
	block[5] = tableS3[0x900+int(block[1])]
	block[1] = tableS3[0x500+int(tmp)]

	tmp = block[2]
	block[2] = tableS3[0xa00+int(block[10])]
	block[10] = tableS3[0x200+int(tmp)]
	tmp = block[6]
	block[6] = tableS3[0xe00+int(block[14])]
	block[14] = tableS3[0x600+int(tmp)]

	tmp = block[3]
	block[3] = tableS3[0xf00+int(block[7])]
	block[7] = tableS3[0x300+int(block[11])]
	block[11] = tableS3[0x700+int(block[15])]
	block[15] = tableS3[0xb00+int(tmp)]
}

func permuteBlock2(block []byte, round int) {
	block[0] = permuteTable2(round*16+0)[block[0]]
	block[4] = permuteTable2(round*16+4)[block[4]]
	block[8] = permuteTable2(round*16+8)[block[8]]
	block[12] = permuteTable2(round*16+12)[block[12]]

	tmp := block[13]
	block[13] = permuteTable2(round*16+13)[block[9]]
	block[9] = permuteTable2(round*16+9)[block[5]]
	block[5] = permuteTable2(round*16+5)[block[1]]
	block[1] = permuteTable2(round*16+1)[tmp]

	tmp = block[2]
	block[2] = permuteTable2(round*16+2)[block[10]]
	block[10] = permuteTable2(round*16+10)[tmp]
	tmp = block[6]
	block[6] = permuteTable2(round*16+6)[block[14]]
	block[14] = permuteTable2(round*16+14)[tmp]

	tmp = block[3]
	block[3] = permuteTable2(round*16+3)[block[7]]
	block[7] = permuteTable2(round*16+7)[block[11]]
	block[11] = permuteTable2(round*16+11)[block[15]]
	block[15] = permuteTable2(round*16+15)[tmp]
}

// generateKeySchedule expands 16 bytes of key material into 11 round keys.
func generateKeySchedule(keyMaterial []byte, keySchedule *[11][4]uint32) {
	var buf [16]byte
	tXor(keyMaterial, buf[:])
	word := func(k int) uint32 { return binary.LittleEndian.Uint32(buf[4*k:]) }
	setWord := func(k int, v uint32) { binary.LittleEndian.PutUint32(buf[4*k:], v) }

	ti := 0
	for round := 0; round < 11; round++ {
		keySchedule[round][0] = word(0)

		table1 := tableIndex(ti)
		table2 := tableIndex(ti + 1)
		table3 := tableIndex(ti + 2)
		table4 := tableIndex(ti + 3)
		ti += 4

		buf[0] ^= table1[buf[0x0d]] ^ indexMangle[round]
		buf[1] ^= table2[buf[0x0e]]
		buf[2] ^= table3[buf[0x0f]]
		buf[3] ^= table4[buf[0x0c]]

		keySchedule[round][1] = word(1)
		setWord(1, word(1)^word(0))

		keySchedule[round][2] = word(2)
		setWord(2, word(2)^word(1))

		keySchedule[round][3] = word(3)
		setWord(3, word(3)^word(2))
	}
}

// cycle runs the 9-round block transformation in place on a 16-byte block.
func cycle(block []byte, keySchedule *[11][4]uint32) {
	word := func(k int) uint32 { return binary.LittleEndian.Uint32(block[4*k:]) }
	setWord := func(k int, v uint32) { binary.LittleEndian.PutUint32(block[4*k:], v) }

	setWord(0, word(0)^keySchedule[10][0])
	setWord(1, word(1)^keySchedule[10][1])
	setWord(2, word(2)^keySchedule[10][2])
	setWord(3, word(3)^keySchedule[10][3])

	permuteBlock1(block)

	for round := 0; round < 9; round++ {
		ks := keySchedule[9-round]
		var k0, k1, k2, k3 [4]byte
		binary.LittleEndian.PutUint32(k0[:], ks[0])
		binary.LittleEndian.PutUint32(k1[:], ks[1])
		binary.LittleEndian.PutUint32(k2[:], ks[2])
		binary.LittleEndian.PutUint32(k3[:], ks[3])

		ab := tableS5[block[3]^k0[3]] ^
			tableS6[block[2]^k0[2]] ^
			tableS8[block[0]^k0[0]] ^
			tableS7[block[1]^k0[1]]
		setWord(0, ab)

		ab = tableS5[block[7]^k1[3]] ^
			tableS6[block[6]^k1[2]] ^
			tableS7[block[5]^k1[1]] ^
			tableS8[block[4]^k1[0]]
		setWord(1, ab)

		setWord(2, tableS5[block[11]^k2[3]]^
			tableS6[block[10]^k2[2]]^
			tableS7[block[9]^k2[1]]^
			tableS8[block[8]^k2[0]])

		setWord(3, tableS5[block[15]^k3[3]]^
			tableS6[block[14]^k3[2]]^
			tableS7[block[13]^k3[1]]^
			tableS8[block[12]^k3[0]])

		permuteBlock2(block, 8-round)
	}

	setWord(0, word(0)^keySchedule[0][0])
	setWord(1, word(1)^keySchedule[0][1])
	setWord(2, word(2)^keySchedule[0][2])
	setWord(3, word(3)^keySchedule[0][3])
}

// decryptMessage decrypts the 128 bytes of payload in a 164-byte FairPlay
// handshake message (the first 16 bytes are a header).
func decryptMessage(messageIn []byte, decryptedMessage []byte) {
	var buffer [16]byte
	mode := int(messageIn[12]) // 0, 1, 2 or 3

	for i := 0; i < 8; i++ {
		// Copy in the nth block (mode 3 walks the message backwards).
		for j := 0; j < 16; j++ {
			if mode == 3 {
				buffer[j] = messageIn[(0x80-0x10*i)+j]
			} else {
				buffer[j] = messageIn[(0x10*(i+1))+j]
			}
		}

		// Nine rounds of table permutation + tableS9 word mixing.
		for j := 0; j < 9; j++ {
			base := 0x80 - 0x10*j

			buffer[0x0] = messageTableIndex(base+0x0)[buffer[0x0]] ^ messageKey[mode][base+0x0]
			buffer[0x4] = messageTableIndex(base+0x4)[buffer[0x4]] ^ messageKey[mode][base+0x4]
			buffer[0x8] = messageTableIndex(base+0x8)[buffer[0x8]] ^ messageKey[mode][base+0x8]
			buffer[0xc] = messageTableIndex(base+0xc)[buffer[0xc]] ^ messageKey[mode][base+0xc]

			tmp := buffer[0x0d]
			buffer[0xd] = messageTableIndex(base+0xd)[buffer[0x9]] ^ messageKey[mode][base+0xd]
			buffer[0x9] = messageTableIndex(base+0x9)[buffer[0x5]] ^ messageKey[mode][base+0x9]
			buffer[0x5] = messageTableIndex(base+0x5)[buffer[0x1]] ^ messageKey[mode][base+0x5]
			buffer[0x1] = messageTableIndex(base+0x1)[tmp] ^ messageKey[mode][base+0x1]

			tmp = buffer[0x02]
			buffer[0x2] = messageTableIndex(base+0x2)[buffer[0xa]] ^ messageKey[mode][base+0x2]
			buffer[0xa] = messageTableIndex(base+0xa)[tmp] ^ messageKey[mode][base+0xa]
			tmp = buffer[0x06]
			buffer[0x6] = messageTableIndex(base+0x6)[buffer[0xe]] ^ messageKey[mode][base+0x6]
			buffer[0xe] = messageTableIndex(base+0xe)[tmp] ^ messageKey[mode][base+0xe]

			tmp = buffer[0x3]
			buffer[0x3] = messageTableIndex(base+0x3)[buffer[0x7]] ^ messageKey[mode][base+0x3]
			buffer[0x7] = messageTableIndex(base+0x7)[buffer[0xb]] ^ messageKey[mode][base+0x7]
			buffer[0xb] = messageTableIndex(base+0xb)[buffer[0xf]] ^ messageKey[mode][base+0xb]
			buffer[0xf] = messageTableIndex(base+0xf)[tmp] ^ messageKey[mode][base+0xf]

			binary.LittleEndian.PutUint32(buffer[0:], tableS9[0x000+int(buffer[0x0])]^
				tableS9[0x100+int(buffer[0x1])]^
				tableS9[0x200+int(buffer[0x2])]^
				tableS9[0x300+int(buffer[0x3])])
			binary.LittleEndian.PutUint32(buffer[4:], tableS9[0x000+int(buffer[0x4])]^
				tableS9[0x100+int(buffer[0x5])]^
				tableS9[0x200+int(buffer[0x6])]^
				tableS9[0x300+int(buffer[0x7])])
			binary.LittleEndian.PutUint32(buffer[8:], tableS9[0x000+int(buffer[0x8])]^
				tableS9[0x100+int(buffer[0x9])]^
				tableS9[0x200+int(buffer[0xa])]^
				tableS9[0x300+int(buffer[0xb])])
			binary.LittleEndian.PutUint32(buffer[12:], tableS9[0x000+int(buffer[0xc])]^
				tableS9[0x100+int(buffer[0xd])]^
				tableS9[0x200+int(buffer[0xe])]^
				tableS9[0x300+int(buffer[0xf])])
		}

		// Final permutation through tableS10.
		buffer[0x0] = tableS10[(0x0<<8)+int(buffer[0x0])]
		buffer[0x4] = tableS10[(0x4<<8)+int(buffer[0x4])]
		buffer[0x8] = tableS10[(0x8<<8)+int(buffer[0x8])]
		buffer[0xc] = tableS10[(0xc<<8)+int(buffer[0xc])]

		tmp := buffer[0x0d]
		buffer[0xd] = tableS10[(0xd<<8)+int(buffer[0x9])]
		buffer[0x9] = tableS10[(0x9<<8)+int(buffer[0x5])]
		buffer[0x5] = tableS10[(0x5<<8)+int(buffer[0x1])]
		buffer[0x1] = tableS10[(0x1<<8)+int(tmp)]

		tmp = buffer[0x02]
		buffer[0x2] = tableS10[(0x2<<8)+int(buffer[0xa])]
		buffer[0xa] = tableS10[(0xa<<8)+int(tmp)]
		tmp = buffer[0x06]
		buffer[0x6] = tableS10[(0x6<<8)+int(buffer[0xe])]
		buffer[0xe] = tableS10[(0xe<<8)+int(tmp)]

		tmp = buffer[0x3]
		buffer[0x3] = tableS10[(0x3<<8)+int(buffer[0x7])]
		buffer[0x7] = tableS10[(0x7<<8)+int(buffer[0xb])]
		buffer[0xb] = tableS10[(0xb<<8)+int(buffer[0xf])]
		buffer[0xf] = tableS10[(0xf<<8)+int(tmp)]

		// XOR with the previous message block (or the mode IV at the ends).
		if mode == 2 || mode == 1 || mode == 0 {
			if i > 0 {
				xorBlocks(buffer[:], messageIn[0x10*i:0x10*i+16], decryptedMessage[0x10*i:0x10*i+16])
			} else {
				xorBlocks(buffer[:], messageKeyIV(mode), decryptedMessage[0:16])
			}
		} else {
			off := 0x70 - 0x10*i
			if i < 7 {
				xorBlocks(buffer[:], messageIn[off:off+16], decryptedMessage[off:off+16])
			} else {
				xorBlocks(buffer[:], messageKeyIV(mode), decryptedMessage[off:off+16])
			}
		}
	}
}

func messageKeyIV(mode int) []byte {
	return messageIv[mode][:]
}

// generateSessionKey derives the 16-byte session key from the SAP blob and
// the (decrypted) handshake message.
func generateSessionKey(oldSap []byte, messageIn []byte) []byte {
	decryptedMessage := make([]byte, 128)
	decryptMessage(messageIn, decryptedMessage)

	newSap := make([]byte, 320)
	copy(newSap[0x000:], staticSource1[:0x11])
	copy(newSap[0x011:], decryptedMessage[:0x80])
	copy(newSap[0x091:], oldSap[0x80:0x80+0x80])
	copy(newSap[0x111:], staticSource2[:0x2f])

	sessionKey := make([]byte, 16)
	copy(sessionKey, initialSessionKey)

	md5Out := make([]byte, 16)
	for round := 0; round < 5; round++ {
		base := newSap[round*64 : round*64+64]
		modifiedMD5(base, sessionKey, md5Out)
		sapHash(base, sessionKey)
		for i := 0; i < 4; i++ {
			sk := binary.LittleEndian.Uint32(sessionKey[4*i:])
			mv := binary.LittleEndian.Uint32(md5Out[4*i:])
			binary.LittleEndian.PutUint32(sessionKey[4*i:], sk+mv)
		}
	}

	// Reverse the bytes inside each 4-byte word.
	for i := 0; i < 16; i += 4 {
		sessionKey[i], sessionKey[i+3] = sessionKey[i+3], sessionKey[i]
		sessionKey[i+1], sessionKey[i+2] = sessionKey[i+2], sessionKey[i+1]
	}

	for i := 0; i < 16; i++ {
		sessionKey[i] ^= 121
	}
	return sessionKey
}

// --- modified MD5 (sap_hash.c / modified_md5.c companions) ---

var md5Shift = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

// md5K[i] = floor(2^32 * abs(sin(i+1))), the standard MD5 sine table.
var md5K = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

func modifiedMD5(originalBlockIn []byte, keyIn []byte, keyOut []byte) {
	blockIn := make([]byte, 64)
	copy(blockIn, originalBlockIn[:64])

	keyWord := func(k int) uint32 { return binary.LittleEndian.Uint32(keyIn[4*k:]) }
	blockWord := func(k int) uint32 { return binary.LittleEndian.Uint32(blockIn[4*k:]) }
	setBlockWord := func(k int, v uint32) { binary.LittleEndian.PutUint32(blockIn[4*k:], v) }
	swapWords := func(a, b int) {
		va, vb := blockWord(a), blockWord(b)
		setBlockWord(a, vb)
		setBlockWord(b, va)
	}

	A, B, C, D := keyWord(0), keyWord(1), keyWord(2), keyWord(3)
	for i := 0; i < 64; i++ {
		var j int
		switch {
		case i < 16:
			j = i
		case i < 32:
			j = (5*i + 1) % 16
		case i < 48:
			j = (3*i + 5) % 16
		default:
			j = (7 * i) % 16
		}

		// Note: the message word is assembled big-endian, unlike stock MD5.
		input := binary.BigEndian.Uint32(blockIn[4*j:])
		Z := A + input + md5K[i]
		var f uint32
		switch {
		case i < 16:
			f = (B & C) | (^B & D)
		case i < 32:
			f = (B & D) | (C & ^D)
		case i < 48:
			f = B ^ C ^ D
		default:
			f = C ^ (B | ^D)
		}
		Z = bits.RotateLeft32(Z+f, md5Shift[i])
		Z = Z + B

		tmp := D
		D = C
		C = B
		B = Z
		A = tmp

		if i == 31 {
			// Mid-hash swap of message words, driven by the state nibbles.
			swapWords(int(A&15), int(B&15))
			swapWords(int(C&15), int(D&15))
			swapWords(int((A&(15<<4))>>4), int((B&(15<<4))>>4))
			swapWords(int((A&(15<<8))>>8), int((B&(15<<8))>>8))
			swapWords(int((A&(15<<12))>>12), int((B&(15<<12))>>12))
		}
	}

	binary.LittleEndian.PutUint32(keyOut[0:], keyWord(0)+A)
	binary.LittleEndian.PutUint32(keyOut[4:], keyWord(1)+B)
	binary.LittleEndian.PutUint32(keyOut[8:], keyWord(2)+C)
	binary.LittleEndian.PutUint32(keyOut[12:], keyWord(3)+D)
}

// --- sap_hash and its garble helper ---

// rol8 rotates a byte left by count (1..7).
func rol8(input byte, count int) byte {
	return byte((uint32(input)<<count)&0xff) | (input >> (8 - count))
}

// rol8x is the unmasked variant: the shifted-out bits are kept above bit 8.
func rol8x(input byte, count int) uint32 {
	return (uint32(input) << count) | (uint32(input) >> (8 - count))
}

func weirdRor8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return ((uint32(input) >> count) & 0xff) | ((uint32(input) & 0xff) << (8 - count))
}

func weirdRol8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return ((uint32(input) << count) & 0xff) | ((uint32(input) & 0xff) >> (8 - count))
}

func weirdRol32(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return (uint32(input) << count) ^ (uint32(input) >> (8 - count))
}

// sapHash hashes a 64-byte block into the 16-byte keyOut (in place).
func sapHash(blockIn []byte, keyOut []byte) {
	buffer0 := []byte{0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC, 0x22, 0x03, 0xD1, 0x20, 0x8F}
	buffer1 := make([]byte, 210)
	buffer2 := []byte{0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20, 0x9D, 0x42, 0x3A}
	buffer3 := make([]byte, 132)
	buffer4 := []byte{0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7}
	i0Index := [11]int{18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30}

	// Load the input, reversing the bytes of each 4-byte word.
	for i := 0; i < 210; i++ {
		inWord := binary.LittleEndian.Uint32(blockIn[4*((i%64)>>2):])
		inByte := (inWord >> ((3 - (i % 4)) << 3)) & 0xff
		buffer1[i] = byte(inByte)
	}

	// Scramble buffer1 (indices are unsigned 32-bit modulo 210).
	for i := 0; i < 840; i++ {
		x := buffer1[uint32(i-155)%210]
		y := buffer1[uint32(i-57)%210]
		z := buffer1[uint32(i-13)%210]
		w := buffer1[uint32(i)%210]
		buffer1[i%210] = byte(int(rol8(y, 5)) + int(rol8(z, 3)^w) - int(rol8(x, 7)))
	}

	garble(buffer0, buffer1, buffer2, buffer3, buffer4)

	for i := 0; i < 16; i++ {
		keyOut[i] = 0xE1
	}
	for i := 0; i < 11; i++ {
		if i == 3 {
			keyOut[i] = 0x3d
		} else {
			keyOut[i] = byte(uint32(keyOut[i]) + uint32(buffer3[i0Index[i]*4]))
		}
	}
	for i := 0; i < 20; i++ {
		keyOut[i%16] ^= buffer0[i]
	}
	for i := 0; i < 35; i++ {
		keyOut[i%16] ^= buffer2[i]
	}
	for i := 0; i < 210; i++ {
		keyOut[i%16] ^= buffer1[i]
	}

	// Reverse scramble.
	for j := 0; j < 16; j++ {
		for i := 0; i < 16; i++ {
			x := keyOut[uint32(i-7)%16]
			y := keyOut[i%16]
			z := keyOut[uint32(i-37)%16]
			w := keyOut[uint32(i-177)%16]
			keyOut[i] = rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5)
		}
	}
}

// garble mutates the five sapHash buffers in place. All arithmetic is done
// in uint32, which reproduces the C code's wrapping int/unsigned-int
// behaviour at byte granularity; every store truncates to a byte, exactly
// like the C unsigned char assignments.
func garble(buffer0, buffer1, buffer2, buffer3, buffer4 []byte) {
	var tmp, tmp2, tmp3 uint32
	var A, B, C, D, E, M, J, G, F, H, K, R, S, T, U, V, W, X, Y, Z uint32

	buffer2[12] = byte(0x14 + (((uint32(buffer1[64]) & 92) | ((uint32(buffer1[99]) / 3) & 35)) & uint32(buffer4[rol8x(buffer4[buffer1[206]%21], 4)%21])))

	buffer1[4] = byte((uint32(buffer1[99]) / 5) * (uint32(buffer1[99]) / 5) * 2)

	buffer2[34] = 0xb8

	buffer1[153] ^= byte(uint32(buffer2[buffer1[203]%35]) * uint32(buffer2[buffer1[203]%35]) * uint32(buffer1[190]))

	buffer0[3] = byte(uint32(buffer0[3]) - (((uint32(buffer4[buffer1[205]%21]) >> 1) & 80) | 0xe6440))

	buffer0[16] = 0x93
	buffer0[13] = 0x62

	buffer1[33] = byte(uint32(buffer1[33]) - (uint32(buffer4[buffer1[36]%21]) & 0xf6))

	tmp2 = uint32(buffer2[buffer1[67]%35])
	buffer2[12] = 0x07

	tmp = uint32(buffer0[buffer1[181]%20])
	buffer1[2] = byte(uint32(buffer1[2]) - 3136)

	buffer0[19] = buffer4[buffer1[58]%21]

	buffer3[0] = byte(92 - uint32(buffer2[buffer1[32]%35]))

	buffer3[4] = byte(uint32(buffer2[buffer1[15]%35]) + 0x9e)

	buffer1[34] = byte(uint32(buffer1[34]) + (uint32(buffer4[((uint32(buffer2[buffer1[15]%35])+0x9e)&0xff)%21]) / 5))

	buffer0[19] = byte(uint32(buffer0[19]) + 0xfffffee6 - ((uint32(buffer0[buffer3[4]%20]) >> 1) & 102))

	{
		v := uint32(buffer4[buffer1[190]%21])
		shift := (7 - (v - 1)) & 7 // C: (7 - (buffer4[...]-1) & 7), '-' binds tighter than '&'
		t := 3 * (((uint32(buffer1[72]) >> (v & 7)) ^ (uint32(buffer1[72]) << shift)) - (3 * uint32(buffer4[buffer1[126]%21])))
		buffer1[15] = byte(t ^ uint32(buffer1[15]))
	}

	buffer0[15] ^= byte(uint32(buffer2[buffer1[181]%35]) * uint32(buffer2[buffer1[181]%35]) * uint32(buffer2[buffer1[181]%35]))

	buffer2[4] ^= byte(uint32(buffer1[202]) / 3)

	A = 92 - uint32(buffer0[buffer3[0]%20])
	E = (A & 0xc6) | ((^uint32(buffer1[105])) & 0xc6) | (A & (^uint32(buffer1[105])))
	buffer2[1] = byte(uint32(buffer2[1]) + (E * E * E))

	buffer0[19] ^= byte(((224 | (uint32(buffer4[buffer1[92]%21]) & 27)) * uint32(buffer2[buffer1[41]%35])) / 3)

	buffer1[140] = byte(uint32(buffer1[140]) + weirdRor8(92, int(buffer1[5]&7)))

	buffer2[12] = byte(uint32(buffer2[12]) + (((((^uint32(buffer1[4])) ^ uint32(buffer2[buffer1[12]%35])) | uint32(buffer1[182])) & 192) | (((^uint32(buffer1[4])) ^ uint32(buffer2[buffer1[12]%35])) & uint32(buffer1[182]))))

	buffer1[36] = byte(uint32(buffer1[36]) + 125)

	buffer1[124] = byte(rol8x(byte((((74&uint32(buffer1[138]))|((74|uint32(buffer1[138]))&uint32(buffer0[15])))&uint32(buffer0[buffer1[43]%20]))|((((74&uint32(buffer1[138]))|((74|uint32(buffer1[138]))&uint32(buffer0[15])))|uint32(buffer0[buffer1[43]%20]))&95)), 4))

	buffer3[8] = byte(((((uint32(buffer0[buffer3[4]%20]) & 95)) & ((uint32(buffer4[buffer1[68]%21]) & 46) << 1)) | 16) ^ 92)

	A = uint32(buffer1[177]) + uint32(buffer4[buffer1[79]%21])
	D = (((A >> 1) | ((3 * uint32(buffer1[148])) / 5)) & uint32(buffer2[1])) | ((A >> 1) & ((3 * uint32(buffer1[148])) / 5))
	buffer3[12] = byte(-(34 + D))

	A = 8 - (uint32(buffer2[22]) & 7)
	B = uint32(buffer1[33]) >> (A & 7)
	C = uint32(buffer1[33]) << (uint32(buffer2[22]) & 7)
	buffer2[16] = byte(uint32(buffer2[16]) + (((uint32(buffer2[buffer3[0]%35]) & 159) | uint32(buffer0[buffer3[4]%20]) | 8) - ((B ^ C) | 128)))

	buffer0[14] ^= buffer2[buffer3[12]%35]

	A = weirdRol8(buffer4[buffer0[buffer1[201]%20]%21], int((uint32(buffer2[buffer1[112]%35])<<1)&7))
	D = (uint32(buffer0[buffer1[208]%20]) & 131) | (uint32(buffer0[buffer1[164]%20]) & 124)
	buffer1[19] = byte(uint32(buffer1[19]) + ((A & (D / 5)) | ((A | (D / 5)) & 37)))

	buffer2[8] = byte(weirdRor8(140, int(((uint32(buffer4[buffer1[45]%21])+92)*(uint32(buffer4[buffer1[45]%21])+92))&7)))

	buffer1[190] = 56

	buffer2[8] ^= buffer3[0]

	buffer1[53] = byte(^((uint32(buffer0[buffer1[83]%20]) | 204) / 5))

	buffer0[13] = byte(uint32(buffer0[13]) + uint32(buffer0[buffer1[41]%20]))

	buffer0[10] = byte(((uint32(buffer2[buffer3[0]%35]) & uint32(buffer1[2])) | ((uint32(buffer2[buffer3[0]%35]) | uint32(buffer1[2])) & uint32(buffer3[12]))) / 15)

	A = (((56 | (uint32(buffer4[buffer1[2]%21]) & 68)) | uint32(buffer2[buffer3[8]%35])) & 42) | (((uint32(buffer4[buffer1[2]%21]) & 68) | 56) & uint32(buffer2[buffer3[8]%35]))
	buffer3[16] = byte((A * A) + 110)

	buffer3[20] = byte(202 - uint32(buffer3[16]))

	buffer3[24] = buffer1[151]

	buffer2[13] ^= buffer4[buffer3[0]%21]

	B = ((uint32(buffer2[buffer1[179]%35]) - 38) & 177) | (uint32(buffer3[12]) & 177)
	C = ((uint32(buffer2[buffer1[179]%35]) - 38)) & uint32(buffer3[12])
	buffer3[28] = byte(30 + ((B | C) * (B | C)))

	buffer3[32] = byte(uint32(buffer3[28]) + 62)

	A = ((uint32(buffer3[20]) + (uint32(buffer3[0]) & 74)) | (^uint32(buffer4[buffer3[0]%21]))) & 121
	B = ((uint32(buffer3[20]) + (uint32(buffer3[0]) & 74))) & (^uint32(buffer4[buffer3[0]%21]))
	tmp3 = (A | B)
	C = ((((A | B) ^ 0xffffffa6) | uint32(buffer3[0])) & 4) | (((A | B) ^ 0xffffffa6) & uint32(buffer3[0]))
	buffer1[47] = byte((uint32(buffer2[buffer1[89]%35]) + C) ^ uint32(buffer1[47]))

	buffer3[36] = byte(((uint32(rol8(byte((tmp&179)+68), 2)) & uint32(buffer0[3])) | (tmp2 & (^uint32(buffer0[3])))) - 15)

	buffer1[123] ^= 221

	A = (uint32(buffer4[buffer3[0]%21]) / 3) - uint32(buffer2[buffer3[4]%35])
	C = (((uint32(buffer3[0]) & 163) + 92) & 246) | (uint32(buffer3[0]) & 92)
	E = ((C | uint32(buffer3[24])) & 54) | (C & uint32(buffer3[24]))
	buffer3[40] = byte(A - E)

	buffer3[44] = byte(tmp3 ^ 81 ^ (((uint32(buffer3[0]) >> 1) & 101) + 26))

	buffer3[48] = byte(uint32(buffer2[buffer3[4]%35]) & 27)
	buffer3[52] = 27
	buffer3[56] = 199

	{
		a := ((uint32(buffer3[40]) | uint32(buffer3[24])) & 177) | (uint32(buffer3[40]) & uint32(buffer3[24]))
		b := ((uint32(buffer4[buffer3[0]%20]) & 177) | 176) | (uint32(buffer4[buffer3[0]%21]) & (^uint32(3)))
		lhs := a & b
		c1 := ((uint32(buffer3[40]) & uint32(buffer3[24])) | ((uint32(buffer3[40]) | uint32(buffer3[24])) & 177)) & 199
		c2 := (((uint32(buffer4[buffer3[0]%21]) & 1) + 176) | (uint32(buffer4[buffer3[0]%21]) & (^uint32(3)))) & uint32(buffer3[56])
		mid := lhs | (c1 | c2)
		buffer3[64] = byte(uint32(buffer3[4]) + ((mid & (^uint32(buffer3[52]))) | uint32(buffer3[48])))
	}

	buffer2[33] ^= buffer1[26]

	buffer1[106] ^= buffer3[20] ^ 133

	buffer2[30] = byte(((uint32(buffer3[64]) / 3) - (275 | (uint32(buffer3[0]) & 247))) ^ uint32(buffer0[buffer1[122]%20]))

	buffer1[22] = byte((uint32(buffer2[buffer1[90]%35]) & 95) | 68)

	A = (uint32(buffer4[buffer3[36]%21]) & 184) | (uint32(buffer2[buffer3[44]%35]) & (^uint32(184)))
	buffer2[18] = byte(uint32(buffer2[18]) + ((A * A * A) >> 1))

	buffer2[5] = byte(uint32(buffer2[5]) - uint32(buffer4[buffer1[92]%21]))

	A = (((uint32(buffer1[41]) & (^uint32(24))) | (uint32(buffer2[buffer1[183]%35]) & 24)) & (uint32(buffer3[16]) + 53)) | (uint32(buffer3[20]) & uint32(buffer2[buffer3[20]%35]))
	B = (uint32(buffer1[17]) & (^uint32(buffer3[44]))) | (uint32(buffer0[buffer1[59]%20]) & uint32(buffer3[44]))
	buffer2[18] ^= byte(A * B)

	A = weirdRor8(buffer1[11], int(uint32(buffer2[buffer1[28]%35])&7)) & 7
	B = (((uint32(buffer0[buffer1[93]%20]) & (^uint32(buffer0[14]))) | (uint32(buffer0[14]) & 150)) & (^uint32(28))) | (uint32(buffer1[7]) & 28)
	buffer2[22] = byte(((((B | weirdRol8(buffer2[buffer3[0]%35], int(A))) & uint32(buffer2[33])) | (B & weirdRol8(buffer2[buffer3[0]%35], int(A)))) + 74) & 0xff)

	A = uint32(buffer4[(uint32(buffer0[buffer1[39]%20])^217)%21])
	buffer0[15] = byte(uint32(buffer0[15]) - (((((uint32(buffer3[20]) | uint32(buffer3[0])) & 214) | (uint32(buffer3[20]) & uint32(buffer3[0]))) & A) | ((((uint32(buffer3[20]) | uint32(buffer3[0])) & 214) | (uint32(buffer3[20]) & uint32(buffer3[0])) | A) & uint32(buffer3[32]))))

	B = (((uint32(buffer2[buffer1[57]%35]) & uint32(buffer0[buffer3[64]%20])) | ((uint32(buffer0[buffer3[64]%20]) | uint32(buffer2[buffer1[57]%35])) & 95) | (uint32(buffer3[64]) & 45) | 82) & 32)
	C = ((uint32(buffer2[buffer1[57]%35]) & uint32(buffer0[buffer3[64]%20])) | ((uint32(buffer2[buffer1[57]%35]) | uint32(buffer0[buffer3[64]%20])) & 95)) & ((uint32(buffer3[64]) & 45) | 82)
	D = (((uint32(buffer3[0]) / 3) - (uint32(buffer3[64]) | uint32(buffer1[22]))) ^ (uint32(buffer3[28]) + 62) ^ (B | C))
	T = uint32(buffer0[(D&0xff)%20])

	buffer3[68] = byte((uint32(buffer0[buffer1[99]%20]) * uint32(buffer0[buffer1[99]%20]) * uint32(buffer0[buffer1[99]%20]) * uint32(buffer0[buffer1[99]%20])) | uint32(buffer2[buffer3[64]%35]))

	U = uint32(buffer0[buffer1[50]%20])
	W = uint32(buffer2[buffer1[138]%35])
	X = uint32(buffer4[buffer1[39]%21])
	Y = uint32(buffer0[buffer1[4]%20])
	Z = uint32(buffer4[buffer1[202]%21])
	V = uint32(buffer0[buffer1[151]%20])
	S = uint32(buffer2[buffer1[14]%35])
	R = uint32(buffer0[buffer1[145]%20])

	A = (uint32(buffer2[buffer3[68]%35]) & uint32(buffer0[buffer1[209]%20])) | ((uint32(buffer2[buffer3[68]%35]) | uint32(buffer0[buffer1[209]%20])) & 24)
	B = weirdRol8(buffer4[buffer1[127]%21], int(uint32(buffer2[buffer3[68]%35])&7))
	C = (A & uint32(buffer0[10])) | (B & (^uint32(buffer0[10])))
	D = 7 ^ (uint32(buffer4[buffer2[buffer3[36]%35]%21]) << 1)
	buffer3[72] = byte((C & 71) | (D & (^uint32(71))))

	buffer2[2] = byte(uint32(buffer2[2]) + ((((uint32(buffer0[buffer3[20]%20]) << 1) & 159) | (uint32(buffer4[buffer1[190]%21]) & (^uint32(159)))) & ((((uint32(buffer4[buffer3[64]%21]) & 110) | (uint32(buffer0[buffer1[25]%20]) & (^uint32(110)))) & (^uint32(150))) | (uint32(buffer1[25]) & 150))))

	buffer2[14] = byte(uint32(buffer2[14]) - (((uint32(buffer2[buffer3[20]%35]) & (uint32(buffer3[72]) ^ uint32(buffer2[buffer1[100]%35]))) & (^uint32(34))) | (uint32(buffer1[97]) & 34)))

	buffer0[17] = 115

	{
		p := ((uint32(buffer4[buffer1[17]%21]) | uint32(buffer0[buffer3[20]%20])) & uint32(buffer3[72])) | (uint32(buffer4[buffer1[17]%21]) & uint32(buffer0[buffer3[20]%20]))
		q := uint32(buffer1[50]) / 3
		buffer1[23] ^= byte(((p & q) | ((p | q) & 246)) << 1)
	}

	buffer0[13] = byte((((((uint32(buffer0[buffer3[40]%20]) | uint32(buffer1[10])) & 82) | (uint32(buffer0[buffer3[40]%20]) & uint32(buffer1[10]))) & 209) | ((uint32(buffer0[buffer1[39]%20]) << 1) & 46)) >> 1)

	buffer2[33] = byte(uint32(buffer2[33]) - (uint32(buffer1[113]) & 9))

	buffer2[28] = byte(uint32(buffer2[28]) - ((((2 | (uint32(buffer1[110]) & 222)) >> 1) & (^uint32(223))) | (uint32(buffer3[20]) & 223)))

	J = weirdRol8(byte(V|Z), int(U&7))
	A = (uint32(buffer2[16]) & T) | (W & (^uint32(buffer2[16])))
	B = (uint32(buffer1[33]) & 17) | (X & (^uint32(17)))
	E = ((Y | ((A + B) / 5)) & 147) | (Y & ((A + B) / 5))
	M = (uint32(buffer3[40]) & uint32(buffer4[((uint32(buffer3[8])+J+E)&0xff)%21])) | ((uint32(buffer3[40]) | uint32(buffer4[((uint32(buffer3[8])+J+E)&0xff)%21])) & uint32(buffer2[23]))

	buffer0[15] = byte((((uint32(buffer4[buffer3[20]%21]) - 48) & (^uint32(buffer1[184]))) | ((uint32(buffer4[buffer3[20]%21]) - 48) & 189) | (189 & (^uint32(buffer1[184])))) & (M * M * M))

	buffer2[22] = byte(uint32(buffer2[22]) + uint32(buffer1[183]))

	buffer3[76] = byte((3 * uint32(buffer4[buffer1[1]%21])) ^ uint32(buffer3[0]))

	A = uint32(buffer2[((uint32(buffer3[8])+(J+E))&0xff)%35])
	F = (((uint32(buffer4[buffer1[178]%21]) & A) | ((uint32(buffer4[buffer1[178]%21]) | A) & 209)) * uint32(buffer0[buffer1[13]%20])) * (uint32(buffer4[buffer1[26]%21]) >> 1)
	G = (F+0x733ffff9)*198 - (((F+0x733ffff9)*396 + 212) & 212) + 85
	buffer3[80] = byte(uint32(buffer3[36]) + (G ^ 148) + ((G ^ 107) << 1) - 127)

	buffer3[84] = byte((uint32(buffer2[buffer3[64]%35]) & 245) | (uint32(buffer2[buffer3[20]%35]) & 10))

	A = uint32(buffer0[buffer3[68]%20]) | 81
	buffer2[18] = byte(uint32(buffer2[18]) - (((A * A * A) & (^uint32(buffer0[15]))) | ((uint32(buffer3[80]) / 15) & uint32(buffer0[15]))))

	buffer3[88] = byte(uint32(buffer3[8]) + J + E - uint32(buffer0[buffer1[160]%20]) + (uint32(buffer4[buffer0[((uint32(buffer3[8])+J+E)&255)%20]%21]) / 3))

	B = ((R ^ uint32(buffer3[72])) & (^uint32(198))) | ((S * S) & 198)
	F = (uint32(buffer4[buffer1[69]%21]) & uint32(buffer1[172])) | ((uint32(buffer4[buffer1[69]%21]) | uint32(buffer1[172])) & ((uint32(buffer3[12]) - B) + 77))
	buffer0[16] = byte(147 - ((uint32(buffer3[72]) & ((F & 251) | 1)) | (((F & 250) | uint32(buffer3[72])) & 198)))

	C = (uint32(buffer4[buffer1[168]%21]) & uint32(buffer0[buffer1[29]%20]) & 7) | ((uint32(buffer4[buffer1[168]%21]) | uint32(buffer0[buffer1[29]%20])) & 6)
	F = (uint32(buffer4[buffer1[155]%21]) & uint32(buffer1[105])) | ((uint32(buffer4[buffer1[155]%21]) | uint32(buffer1[105])) & 141)
	buffer0[3] = byte(uint32(buffer0[3]) - uint32(buffer4[weirdRol32(byte(F), int(C))%21]))

	buffer1[5] = byte(weirdRor8(buffer0[12], int((uint32(buffer0[buffer1[61]%20])/5)&7)) ^ ((^uint32(buffer2[buffer3[84]%35])) / 5))

	buffer1[198] = byte(uint32(buffer1[198]) + uint32(buffer1[3]))

	A = (162 | uint32(buffer2[buffer3[64]%35]))
	buffer1[164] = byte(uint32(buffer1[164]) + ((A * A) / 5))

	G = weirdRor8(139, int(buffer3[80]&7))
	C = ((uint32(buffer4[buffer3[64]%21]) * uint32(buffer4[buffer3[64]%21]) * uint32(buffer4[buffer3[64]%21])) & 95) | (uint32(buffer0[buffer3[40]%20]) & (^uint32(95)))
	buffer3[92] = byte((G & 12) | (uint32(buffer0[buffer3[20]%20]) & 12) | (G & uint32(buffer0[buffer3[20]%20])) | C)

	buffer2[12] = byte(uint32(buffer2[12]) + (((uint32(buffer1[103]) & 32) | (uint32(buffer3[92]) & (uint32(buffer1[103]) | 60)) | 16) / 3))

	buffer3[96] = buffer1[143]
	buffer3[100] = 27

	buffer3[104] = byte((((uint32(buffer3[40]) & (^uint32(buffer2[8]))) | (uint32(buffer1[35]) & uint32(buffer2[8]))) & uint32(buffer3[64])) ^ 119)

	buffer3[108] = byte(238 & ((((uint32(buffer3[40]) & (^uint32(buffer2[8]))) | (uint32(buffer1[35]) & uint32(buffer2[8]))) & uint32(buffer3[64])) << 1))

	buffer3[112] = byte(((^uint32(buffer3[64])) & (uint32(buffer3[84]) / 3)) ^ 49)

	buffer3[116] = byte(98 & (((^uint32(buffer3[64])) & (uint32(buffer3[84]) / 3)) << 1))

	A = (uint32(buffer1[35]) & uint32(buffer2[8])) | (uint32(buffer3[40]) & (^uint32(buffer2[8])))
	B = (A & uint32(buffer3[64])) | (((uint32(buffer3[84]) / 3)) & (^uint32(buffer3[64])))
	buffer1[143] = byte(uint32(buffer3[96]) - ((B & (86 + ((uint32(buffer1[172]) & 64) >> 1))) | (((((uint32(buffer1[172]) & 65) >> 1) ^ 86) | (((^uint32(buffer3[64])) & (uint32(buffer3[84]) / 3)) | (((uint32(buffer3[40]) & (^uint32(buffer2[8]))) | (uint32(buffer1[35]) & uint32(buffer2[8]))) & uint32(buffer3[64])))) & uint32(buffer3[100]))))

	buffer2[29] = 162

	A = (((uint32(buffer4[buffer3[88]%21]) & 160) | (uint32(buffer0[buffer1[125]%20]) & 95)) >> 1)
	B = uint32(buffer2[buffer1[149]%35]) ^ (uint32(buffer1[43]) * uint32(buffer1[43]))
	buffer0[15] = byte(uint32(buffer0[15]) + ((B & A) | ((A | B) & 115)))

	buffer3[120] = byte(uint32(buffer3[64]) - uint32(buffer0[buffer3[40]%20]))

	buffer1[95] = buffer4[buffer3[20]%21]

	A = weirdRor8(buffer2[buffer3[80]%35], int((uint32(buffer2[buffer1[17]%35])*uint32(buffer2[buffer1[17]%35])*uint32(buffer2[buffer1[17]%35]))&7))
	buffer0[7] = byte(uint32(buffer0[7]) - (A * A))

	buffer2[8] = byte(uint32(buffer2[8]) - uint32(buffer1[184]) + (uint32(buffer4[buffer1[202]%21]) * uint32(buffer4[buffer1[202]%21]) * uint32(buffer4[buffer1[202]%21])))

	buffer0[16] = byte((uint32(buffer2[buffer1[102]%35]) << 1) & 132)

	buffer3[124] = byte((uint32(buffer4[buffer3[40]%21]) >> 1) ^ uint32(buffer3[68]))

	buffer0[7] = byte(uint32(buffer0[7]) - (uint32(buffer0[buffer1[191]%20]) - (((uint32(buffer4[buffer1[80]%21]) << 1) & (^uint32(177))) | (uint32(buffer4[buffer4[buffer3[88]%21]%21]) & 177))))

	buffer0[6] = buffer0[buffer1[119]%20]

	A = (uint32(buffer4[buffer1[190]%21]) & (^uint32(209))) | (uint32(buffer1[118]) & 209)
	B = uint32(buffer0[buffer3[120]%20]) * uint32(buffer0[buffer3[120]%20])
	buffer0[12] = byte((uint32(buffer0[buffer3[84]%20]) ^ (uint32(buffer2[buffer1[71]%35]) + uint32(buffer2[buffer1[15]%35]))) & ((A & B) | ((A | B) & 27)))

	B = (uint32(buffer1[32]) & uint32(buffer2[buffer3[88]%35])) | ((uint32(buffer1[32]) | uint32(buffer2[buffer3[88]%35])) & 23)
	D = (((uint32(buffer4[buffer1[57]%21]) * 231) & 169) | (B & 86))
	F = (((uint32(buffer0[buffer1[82]%20]) & (^uint32(29))) | (uint32(buffer4[buffer3[124]%21]) & 29)) & 190) | (uint32(buffer4[(D/5)%21]) & (^uint32(190)))
	H = uint32(buffer0[buffer3[40]%20]) * uint32(buffer0[buffer3[40]%20]) * uint32(buffer0[buffer3[40]%20])
	K = (H & uint32(buffer1[82])) | (H & 92) | (uint32(buffer1[82]) & 92)
	buffer3[128] = byte(((F & K) | ((F | K) & 192)) ^ (D / 5))

	buffer2[25] ^= byte(((uint32(buffer0[buffer3[120]%20]) << 1) * uint32(buffer1[5])) - (weirdRol8(buffer3[76], int(uint32(buffer4[buffer3[124]%21])&7)) & (uint32(buffer3[20]) + 110)))
}
