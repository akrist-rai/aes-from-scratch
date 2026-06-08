package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"aes-from-scratch/aes"
)

func main() {
	// ── AES-128 single block (FIPS 197 Appendix B vector) ──────────────────
	fmt.Println("=== AES-128 Block (FIPS 197 vector) ===")
	key128, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	pt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")

	c128, err := aes.NewCipher(key128)
	if err != nil {
		log.Fatal(err)
	}

	block := make([]byte, 16)
	copy(block, pt)
	fmt.Printf("Plaintext:  %x\n", block)
	c128.Encrypt(block)
	fmt.Printf("Encrypted:  %x\n", block)
	c128.Decrypt(block)
	fmt.Printf("Decrypted:  %x\n\n", block)

	// ── AES-256 CBC ─────────────────────────────────────────────────────────
	fmt.Println("=== AES-256 CBC mode ===")
	key256, _ := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	c256, _ := aes.NewCipher(key256)

	message := []byte("The quick brown fox jumps over the lazy dog — AES from scratch!")
	fmt.Printf("Plaintext:  %q\n", message)

	ciphertext, err := c256.CBCEncrypt(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	recovered, err := c256.CBCDecrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Recovered:  %q\n\n", recovered)

	// ── AES-192 CTR ─────────────────────────────────────────────────────────
	fmt.Println("=== AES-192 CTR mode ===")
	key192, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314151617")
	c192, _ := aes.NewCipher(key192)

	plaintext := []byte("CTR mode turns a block cipher into a stream cipher — no padding!")
	fmt.Printf("Plaintext:  %q\n", plaintext)

	enc, err := c192.CTRCrypt(plaintext, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted:  %x\n", enc)

	dec, err := c192.CTRCrypt(enc, false)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted:  %q\n\n", dec)

	// ── ECB pattern demonstration ────────────────────────────────────────────
	fmt.Println("=== ECB weakness: identical blocks → identical ciphertext ===")
	repeating := []byte("YELLOW SUBMARINEYELLOW SUBMARINE") // two identical 16-byte blocks
	ecbOut, _ := c128.ECBEncrypt(repeating)
	block1 := ecbOut[:16]
	block2 := ecbOut[16:32]
	fmt.Printf("Block 1 ct: %x\n", block1)
	fmt.Printf("Block 2 ct: %x\n", block2)
	if string(block1) == string(block2) {
		fmt.Println("^ Identical — ECB leaks repeated plaintext structure!")
	}
}
