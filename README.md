# AES from Scratch — Go

A complete, dependency-free implementation of AES (Advanced Encryption Standard) written in Go with zero imports from `crypto/aes`. Every byte of the cipher — S-box lookups, GF(2⁸) arithmetic, key expansion, and three modes of operation — is implemented from first principles.

---

## What is AES?

AES (FIPS 197, 2001) is a symmetric block cipher: the same key encrypts and decrypts, and data is processed in fixed-size 128-bit blocks. It replaced DES and is the most widely used cipher in the world — used in TLS, disk encryption, VPNs, and more.

Three key lengths are supported, each affecting the number of rounds:

| Variant  | Key   | Rounds |
|----------|-------|--------|
| AES-128  | 16 B  | 10     |
| AES-192  | 24 B  | 12     |
| AES-256  | 32 B  | 14     |

---

## How AES Works

### The State

AES treats each 16-byte block as a **4×4 matrix of bytes** called the _state_, stored **column-major**:

```
Input bytes:  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff

State matrix:
       col0  col1  col2  col3
row0:   00    44    88    cc
row1:   11    55    99    dd
row2:   22    66    aa    ee
row3:   33    77    bb    ff
```

All four round operations work on this 4×4 state.

---

### The Four Round Operations

#### 1. AddRoundKey

XOR every byte of the state with the corresponding byte from the current round key. This is the only operation that mixes key material into the data.

```
state[row][col] ^= roundKey[col][row]
```

Because XOR is its own inverse, `AddRoundKey` is identical in encryption and decryption.

#### 2. SubBytes (non-linear substitution)

Every byte is replaced with its value from a fixed 256-entry lookup table called the **S-box**. The S-box is constructed using multiplicative inverses in GF(2⁸) followed by an affine transform, giving AES its non-linearity and resistance to linear/differential cryptanalysis.

```
state[row][col] = sbox[ state[row][col] ]
```

Decryption uses the inverse S-box.

#### 3. ShiftRows (byte permutation)

Each row of the state is cyclically shifted left by its row index:

```
Row 0: no shift       [a  b  c  d] → [a  b  c  d]
Row 1: left shift 1   [e  f  g  h] → [f  g  h  e]
Row 2: left shift 2   [i  j  k  l] → [k  l  i  j]
Row 3: left shift 3   [m  n  o  p] → [p  m  n  o]
```

This ensures that bytes from different columns pass through different S-boxes in subsequent rounds (wide-trail strategy). Decryption shifts rows right instead.

#### 4. MixColumns (linear diffusion)

Each column of 4 bytes is treated as a polynomial over GF(2⁸) and multiplied by a fixed matrix:

```
⎡2  3  1  1⎤   ⎡a⎤
⎢1  2  3  1⎥ × ⎢b⎥
⎢1  1  2  3⎥   ⎢c⎥
⎣3  1  1  2⎦   ⎣d⎦
```

Multiplication here is in the Galois field GF(2⁸) with the AES reduction polynomial `x⁸ + x⁴ + x³ + x + 1`. The `xtime` operation (multiply by 2) is a left shift with conditional reduction:

```go
func xtime(b byte) byte {
    if b&0x80 != 0 {
        return (b << 1) ^ 0x1b   // 0x1b = x^4+x^3+x+1
    }
    return b << 1
}
```

MixColumns provides **diffusion** — a 1-bit change in input produces a 4-byte change in the column output. It is skipped in the final round. Decryption uses the inverse MixColumns matrix.

---

### Key Expansion (Key Schedule)

The original key is expanded into `4 × (rounds + 1)` 32-bit words using an algorithm that applies SubBytes and XOR with round constants (Rcon). These words are grouped into per-round keys that are each 128 bits wide.

For AES-128 (4 key words, 10 rounds, 44 total words):

```
w[i] = w[i-4] XOR SubWord(RotWord(w[i-1])) XOR Rcon[i/4]   when i mod 4 == 0
w[i] = w[i-4] XOR w[i-1]                                     otherwise
```

---

### Full Encryption Flow

```
AddRoundKey(state, roundKey[0])

for r = 1 to rounds-1:
    SubBytes(state)
    ShiftRows(state)
    MixColumns(state)
    AddRoundKey(state, roundKey[r])

// Final round — no MixColumns
SubBytes(state)
ShiftRows(state)
AddRoundKey(state, roundKey[rounds])
```

Decryption is the exact reverse using InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns.

---

## Why AES is Secure

| Property         | Provided by             |
|------------------|-------------------------|
| Confusion        | SubBytes (non-linear S-box) |
| Diffusion        | ShiftRows + MixColumns  |
| Key mixing       | AddRoundKey             |
| Brute-force hardness | Key length (128/192/256 bits) |

After just 2 rounds, each output bit depends on every input bit and every key bit. This is called the **avalanche effect**.

---

## Modes of Operation

A block cipher encrypts fixed-size blocks. A **mode of operation** defines how to use a block cipher to encrypt arbitrary-length messages.

### ECB — Electronic Codebook (insecure, for demonstration only)

Each block is encrypted independently with the same key.

```
C[i] = Encrypt(P[i])
```

**Problem:** identical plaintext blocks produce identical ciphertext blocks. The structure of the data is preserved. Famous example: an image of Tux the penguin looks like Tux after ECB encryption.

### CBC — Cipher Block Chaining (recommended)

Each plaintext block is XORed with the previous ciphertext block before encryption. A random **Initialization Vector (IV)** is used for the first block.

```
C[0] = Encrypt(P[0] XOR IV)
C[i] = Encrypt(P[i] XOR C[i-1])
```

CBC hides identical plaintext blocks. The IV is prepended to the ciphertext and must be random (not secret) and never reused with the same key. This implementation generates the IV automatically.

### CTR — Counter Mode (stream cipher)

A counter is encrypted to produce a keystream, which is XORed with the plaintext. Encryption and decryption are the same operation.

```
Keystream[i] = Encrypt(Nonce || Counter[i])
C[i] = P[i] XOR Keystream[i]
```

CTR requires no padding and supports random access. The **nonce must never be reused with the same key** — doing so allows an attacker to recover the XOR of two plaintexts.

---

## Project Layout

```
aes-from-scratch/
├── aes/
│   ├── aes.go        # Core cipher: state, SubBytes, ShiftRows, MixColumns, AddRoundKey, key schedule
│   ├── modes.go      # ECB, CBC, CTR modes + PKCS#7 padding
│   └── aes_test.go   # FIPS 197 known-answer tests + round-trip tests
├── main.go           # Demo showing all three key sizes and modes
├── go.mod
└── README.md
```

---

## Running the Code

```bash
# Run the demo
go run .

# Run all tests (includes FIPS 197 known-answer tests)
go test ./aes/ -v
```

Expected test output:
```
=== RUN   TestAES128BlockEncrypt
--- PASS
=== RUN   TestAES192BlockEncrypt
--- PASS
=== RUN   TestAES256BlockEncrypt
--- PASS
=== RUN   TestAES128BlockDecrypt
--- PASS
=== RUN   TestRoundTrip
--- PASS
=== RUN   TestGmul
--- PASS
```

---

## API

```go
import "aes-from-scratch/aes"

// Create a cipher (key must be 16, 24, or 32 bytes)
c, err := aes.NewCipher(key)

// Single block (16 bytes), in-place
c.Encrypt(block)
c.Decrypt(block)

// ECB mode (avoid in production — no IV, leaks patterns)
ct, err := c.ECBEncrypt(plaintext)
pt, err := c.ECBDecrypt(ciphertext)

// CBC mode — returns IV || ciphertext
ct, err := c.CBCEncrypt(plaintext)
pt, err := c.CBCDecrypt(ct)

// CTR mode — returns nonce || ciphertext when encrypting
ct, err := c.CTRCrypt(plaintext, true)   // encrypt
pt, err := c.CTRCrypt(ct, false)          // decrypt
```

---

## Security Notes

This implementation is for **educational purposes**. It is not constant-time (susceptible to cache-timing attacks) and has not been audited. For production use, use Go's `crypto/aes` from the standard library.
