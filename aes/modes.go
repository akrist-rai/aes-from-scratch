package aes

import (
	"crypto/rand"
	"errors"
	"io"
)

// ─── ECB (Electronic Codebook) ────────────────────────────────────────────────
// Each block is encrypted independently. Simple but NOT semantically secure —
// identical plaintext blocks produce identical ciphertext blocks.

// ECBEncrypt encrypts plaintext using ECB mode with PKCS#7 padding.
func (c *Cipher) ECBEncrypt(plaintext []byte) ([]byte, error) {
	padded := pkcs7Pad(plaintext, BlockSize)
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += BlockSize {
		copy(ciphertext[i:], padded[i:i+BlockSize])
		if err := c.Encrypt(ciphertext[i : i+BlockSize]); err != nil {
			return nil, err
		}
	}
	return ciphertext, nil
}

// ECBDecrypt decrypts ciphertext using ECB mode and removes PKCS#7 padding.
func (c *Cipher) ECBDecrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("aes: ECB ciphertext length is not a multiple of block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += BlockSize {
		copy(plaintext[i:], ciphertext[i:i+BlockSize])
		if err := c.Decrypt(plaintext[i : i+BlockSize]); err != nil {
			return nil, err
		}
	}
	return pkcs7Unpad(plaintext)
}

// ─── CBC (Cipher Block Chaining) ──────────────────────────────────────────────
// Each plaintext block is XORed with the previous ciphertext block before
// encryption. Requires an IV. This is the standard recommended mode for
// block-cipher use when an IV can be stored alongside the ciphertext.

// CBCEncrypt encrypts plaintext using CBC mode.
// Returns iv || ciphertext; the IV is randomly generated.
func (c *Cipher) CBCEncrypt(plaintext []byte) ([]byte, error) {
	iv := make([]byte, BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	padded := pkcs7Pad(plaintext, BlockSize)
	out := make([]byte, BlockSize+len(padded))
	copy(out, iv)

	prev := iv
	for i := 0; i < len(padded); i += BlockSize {
		block := out[BlockSize+i : BlockSize+i+BlockSize]
		copy(block, padded[i:i+BlockSize])
		xorBlock(block, prev) // XOR with previous ciphertext (or IV for first block)
		if err := c.Encrypt(block); err != nil {
			return nil, err
		}
		prev = block
	}
	return out, nil
}

// CBCDecrypt decrypts iv || ciphertext produced by CBCEncrypt.
func (c *Cipher) CBCDecrypt(data []byte) ([]byte, error) {
	if len(data) < BlockSize*2 || len(data)%BlockSize != 0 {
		return nil, errors.New("aes: CBC input too short or not block-aligned")
	}
	iv := data[:BlockSize]
	ciphertext := data[BlockSize:]
	plaintext := make([]byte, len(ciphertext))

	prev := iv
	for i := 0; i < len(ciphertext); i += BlockSize {
		copy(plaintext[i:], ciphertext[i:i+BlockSize])
		if err := c.Decrypt(plaintext[i : i+BlockSize]); err != nil {
			return nil, err
		}
		xorBlock(plaintext[i:i+BlockSize], prev)
		prev = ciphertext[i : i+BlockSize]
	}
	return pkcs7Unpad(plaintext)
}

// ─── CTR (Counter Mode) ───────────────────────────────────────────────────────
// Turns AES into a stream cipher. Encryption and decryption are the same
// operation. No padding needed. The nonce must NEVER be reused with the same key.

// CTRCrypt encrypts or decrypts using CTR mode (they are identical).
// Returns nonce || ciphertext when encrypting; pass the full output back to decrypt.
// If encrypt=true a fresh nonce is generated; if false the first 16 bytes are the nonce.
func (c *Cipher) CTRCrypt(data []byte, encrypt bool) ([]byte, error) {
	var nonce []byte
	var payload []byte

	if encrypt {
		nonce = make([]byte, BlockSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		payload = data
	} else {
		if len(data) < BlockSize {
			return nil, errors.New("aes: CTR input too short")
		}
		nonce = data[:BlockSize]
		payload = data[BlockSize:]
	}

	out := make([]byte, len(payload))
	counter := make([]byte, BlockSize)
	copy(counter, nonce)
	keystream := make([]byte, BlockSize)

	for i := 0; i < len(payload); i += BlockSize {
		copy(keystream, counter)
		if err := c.Encrypt(keystream); err != nil {
			return nil, err
		}
		end := i + BlockSize
		if end > len(payload) {
			end = len(payload)
		}
		for j := i; j < end; j++ {
			out[j] = payload[j] ^ keystream[j-i]
		}
		incrementCounter(counter)
	}

	if encrypt {
		return append(nonce, out...), nil
	}
	return out, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func xorBlock(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func incrementCounter(c []byte) {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			break
		}
	}
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("aes: empty data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > BlockSize || pad > len(data) {
		return nil, errors.New("aes: invalid PKCS#7 padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, errors.New("aes: invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-pad], nil
}
