package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ─── FIPS 197 official test vectors ──────────────────────────────────────────

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAES128BlockEncrypt(t *testing.T) {
	key := mustHex("000102030405060708090a0b0c0d0e0f")
	pt := mustHex("00112233445566778899aabbccddeeff")
	want := mustHex("69c4e0d86a7b0430d8cdb78070b4c55a")

	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, BlockSize)
	copy(block, pt)
	if err := c.Encrypt(block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, want) {
		t.Errorf("AES-128 encrypt: got %x, want %x", block, want)
	}
}

func TestAES192BlockEncrypt(t *testing.T) {
	key := mustHex("000102030405060708090a0b0c0d0e0f1011121314151617")
	pt := mustHex("00112233445566778899aabbccddeeff")
	want := mustHex("dda97ca4864cdfe06eaf70a0ec0d7191")

	c, _ := NewCipher(key)
	block := make([]byte, BlockSize)
	copy(block, pt)
	c.Encrypt(block)
	if !bytes.Equal(block, want) {
		t.Errorf("AES-192 encrypt: got %x, want %x", block, want)
	}
}

func TestAES256BlockEncrypt(t *testing.T) {
	key := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	pt := mustHex("00112233445566778899aabbccddeeff")
	want := mustHex("8ea2b7ca516745bfeafc49904b496089")

	c, _ := NewCipher(key)
	block := make([]byte, BlockSize)
	copy(block, pt)
	c.Encrypt(block)
	if !bytes.Equal(block, want) {
		t.Errorf("AES-256 encrypt: got %x, want %x", block, want)
	}
}

func TestAES128BlockDecrypt(t *testing.T) {
	key := mustHex("000102030405060708090a0b0c0d0e0f")
	ct := mustHex("69c4e0d86a7b0430d8cdb78070b4c55a")
	want := mustHex("00112233445566778899aabbccddeeff")

	c, _ := NewCipher(key)
	block := make([]byte, BlockSize)
	copy(block, ct)
	c.Decrypt(block)
	if !bytes.Equal(block, want) {
		t.Errorf("AES-128 decrypt: got %x, want %x", block, want)
	}
}

func TestRoundTrip(t *testing.T) {
	keySizes := []int{16, 24, 32}
	for _, ks := range keySizes {
		key := make([]byte, ks)
		for i := range key {
			key[i] = byte(i)
		}
		original := []byte("Hello, AES World!")
		c, err := NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		// ECB
		ct, err := c.ECBEncrypt(original)
		if err != nil {
			t.Fatalf("ECB encrypt (keysize=%d): %v", ks, err)
		}
		pt, err := c.ECBDecrypt(ct)
		if err != nil {
			t.Fatalf("ECB decrypt (keysize=%d): %v", ks, err)
		}
		if !bytes.Equal(pt, original) {
			t.Errorf("ECB round-trip failed for keysize %d", ks)
		}

		// CBC
		ct, err = c.CBCEncrypt(original)
		if err != nil {
			t.Fatalf("CBC encrypt (keysize=%d): %v", ks, err)
		}
		pt, err = c.CBCDecrypt(ct)
		if err != nil {
			t.Fatalf("CBC decrypt (keysize=%d): %v", ks, err)
		}
		if !bytes.Equal(pt, original) {
			t.Errorf("CBC round-trip failed for keysize %d", ks)
		}

		// CTR
		ct, err = c.CTRCrypt(original, true)
		if err != nil {
			t.Fatalf("CTR encrypt (keysize=%d): %v", ks, err)
		}
		pt, err = c.CTRCrypt(ct, false)
		if err != nil {
			t.Fatalf("CTR decrypt (keysize=%d): %v", ks, err)
		}
		if !bytes.Equal(pt, original) {
			t.Errorf("CTR round-trip failed for keysize %d", ks)
		}
	}
}

func TestGmul(t *testing.T) {
	// Sample GF(2^8) multiplication checks.
	cases := [][3]byte{
		{0x57, 0x83, 0xc1},
		{0x57, 0x13, 0xfe},
		{0x02, 0x87, 0x15},
	}
	for _, tc := range cases {
		if got := gmul(tc[0], tc[1]); got != tc[2] {
			t.Errorf("gmul(0x%02x, 0x%02x) = 0x%02x, want 0x%02x", tc[0], tc[1], got, tc[2])
		}
	}
}
