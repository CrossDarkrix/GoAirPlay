package main

import (
	"bytes"
	"testing"
)

// TestPlayfairDecryptDeterministic runs the full playfair decryption on
// fixed dummy inputs and checks the output is 16 bytes and deterministic.
// (Correctness against real Apple vectors can only be verified against a
// real client; this guards the port against crashes and nondeterminism.)
func TestPlayfairDecryptDeterministic(t *testing.T) {
	keymsg := make([]byte, 164)
	for i := range keymsg {
		keymsg[i] = byte((i * 7) % 251)
	}
	// FairPlay v3 header with mode byte 1 at offset 12, as a real client sends.
	copy(keymsg, []byte{0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04})
	keymsg[12] = 0x01

	ekey := make([]byte, 72)
	for i := range ekey {
		ekey[i] = byte((i*13 + 5) % 256)
	}

	out1 := playfairDecrypt(keymsg, ekey)
	if len(out1) != 16 {
		t.Fatalf("playfairDecrypt returned %d bytes, want 16", len(out1))
	}
	out2 := playfairDecrypt(keymsg, ekey)
	if !bytes.Equal(out1, out2) {
		t.Fatalf("playfairDecrypt not deterministic: %x vs %x", out1, out2)
	}
	t.Logf("dummy key: %x", out1)
}

// TestPlayfairDecryptModes exercises all four FairPlay modes (the mode is
// selected by byte 12 of the handshake message).
func TestPlayfairDecryptModes(t *testing.T) {
	ekey := make([]byte, 72)
	for i := range ekey {
		ekey[i] = byte(0xa5 ^ i)
	}
	for mode := 0; mode < 4; mode++ {
		keymsg := make([]byte, 164)
		for i := range keymsg {
			keymsg[i] = byte((i*31 + mode*17) % 256)
		}
		copy(keymsg, []byte{0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04})
		keymsg[12] = byte(mode)
		out := playfairDecrypt(keymsg, ekey)
		if len(out) != 16 {
			t.Fatalf("mode %d: got %d bytes, want 16", mode, len(out))
		}
	}
}
