# AES from Scratch — Go

A complete, dependency-free implementation of AES (Advanced Encryption Standard / FIPS 197) written in Go with **zero imports from `crypto/aes`**. Every byte — S-box, GF(2⁸) arithmetic, key expansion, three modes of operation — is implemented from mathematical first principles.

Open [`visualization.html`](visualization.html) in any browser for the full interactive visualization with step-by-step animations, an S-box lookup table, a GF(2⁸) calculator, and a round-by-round encryption trace.

---

## Table of Contents

1. [What AES Is](#what-aes-is)
2. [Mathematical Foundation: GF(2⁸)](#mathematical-foundation-gf28)
3. [The S-Box: Construction from First Principles](#the-s-box-construction-from-first-principles)
4. [The State Matrix](#the-state-matrix)
5. [Round Operations](#round-operations)
   - [AddRoundKey](#addroundkey)
   - [SubBytes / InvSubBytes](#subbytes--invsubbytes)
   - [ShiftRows / InvShiftRows](#shiftrows--invshiftrows)
   - [MixColumns / InvMixColumns](#mixcolumns--invmixcolumns)
6. [Key Expansion (Key Schedule)](#key-expansion-key-schedule)
7. [Full Encryption and Decryption Flow](#full-encryption-and-decryption-flow)
8. [Security Analysis: Why AES Works](#security-analysis-why-aes-works)
9. [Modes of Operation](#modes-of-operation)
10. [FIPS 197 Test Vectors](#fips-197-test-vectors)
11. [Project Layout](#project-layout)
12. [Running the Code](#running-the-code)
13. [API Reference](#api-reference)
14. [Security Notice](#security-notice)

---

## What AES Is

AES is a **symmetric block cipher** — the same key is used for both encryption and decryption. It processes data in **128-bit (16-byte) blocks**, regardless of key size. Three key lengths are supported:

| Variant | Key Length | Rounds (Nr) | Security Level |
|---------|-----------|-------------|----------------|
| AES-128 | 16 bytes  | 10          | 128-bit        |
| AES-192 | 24 bytes  | 12          | 192-bit        |
| AES-256 | 32 bytes  | 14          | 256-bit        |

AES replaced DES in 2001 (NIST FIPS 197) and is the foundation of TLS, disk encryption (FileVault, BitLocker), VPNs, and countless other systems. No practical attack on the full cipher is known.

AES is a **Substitution-Permutation Network (SPN)**. Each round alternates:
- **Non-linear substitution** (SubBytes) — provides *confusion*
- **Linear permutation** (ShiftRows + MixColumns) — provides *diffusion*
- **Key mixing** (AddRoundKey)

After just 2 rounds, every output bit depends on every input bit and every key bit. This is the **avalanche effect**.

---

## Mathematical Foundation: GF(2⁸)

All AES arithmetic — the S-box construction, MixColumns, and key expansion — takes place in the **Galois Field GF(2⁸)**, a finite field with exactly 256 elements.

### What is a finite field?

A field is a set where addition, subtraction, multiplication, and division (by non-zero elements) are all defined and satisfy the usual algebraic laws (commutativity, associativity, distributivity, identities, inverses). GF(2⁸) has exactly 2⁸ = 256 elements — exactly one for each possible byte value, making it a natural fit for byte-oriented computation.

### Representing Elements as Polynomials

Each byte `b` represents a polynomial of degree ≤ 7 with coefficients in GF(2) (i.e., 0 or 1):

```
b = b₇x⁷ + b₆x⁶ + b₅x⁵ + b₄x⁴ + b₃x³ + b₂x² + b₁x + b₀

Example: 0x57 = 0101 0111₂ = x⁶ + x⁴ + x² + x + 1
         0x83 = 1000 0011₂ = x⁷ + x + 1
```

### Addition = XOR

Polynomial addition mod 2 is coefficient-wise XOR. No carries, no borrows:

```
(x⁶ + x⁴ + x² + x + 1) + (x⁷ + x + 1)
  = x⁷ + x⁶ + x⁴ + x² + 2x + 2
  = x⁷ + x⁶ + x⁴ + x²          (coefficients mod 2 → 2x = 0, 2 = 0)

0x57 XOR 0x83 = 0101 0111 XOR 1000 0011 = 1101 0100 = 0xD4  ✓
```

In GF(2), `-1 ≡ 1`, so subtraction and addition are identical operations. Every element is its own additive inverse: `a XOR a = 0`.

### The Reduction Polynomial

Multiplying two degree-7 polynomials can yield degree up to 14. We need to reduce the result back to degree < 8. This requires an **irreducible polynomial** of degree 8 — one that cannot be factored over GF(2).

AES uses:

```
p(x) = x⁸ + x⁴ + x³ + x + 1  =  0x11B
```

This polynomial is irreducible over GF(2) (verified by checking it has no roots and no degree-2, 3, 4 factors). When multiplication produces an x⁸ term, we substitute `x⁸ ≡ x⁴ + x³ + x + 1` (because `p(x) = 0 mod p(x)`). The low 8 bits of `p(x)` are `0x1B`, which is the XOR constant you see throughout the implementation.

### xtime — Multiplication by 2 (by x)

The fundamental GF(2⁸) operation. Multiplying by x = shifting left. If the high bit is set, degree would reach 8, so we reduce:

```go
func xtime(b byte) byte {
    if b&0x80 != 0 {
        return (b << 1) ^ 0x1b   // shift left, reduce by p(x)
    }
    return b << 1
}
```

Powers of `{02}` in GF(2⁸):

| Power | Hex  | Polynomial            |
|-------|------|-----------------------|
| 2⁰    | 01   | 1                     |
| 2¹    | 02   | x                     |
| 2²    | 04   | x²                    |
| 2³    | 08   | x³                    |
| 2⁴    | 10   | x⁴                    |
| 2⁷    | 80   | x⁷                    |
| 2⁸    | 1b   | x⁴+x³+x+1 (reduced)   |
| 2⁹    | 36   | x⁵+x⁴+x²+x            |

### gmul — General Multiplication (Russian Peasant Algorithm)

Any multiplication `a * b` decomposes into powers of 2 using the binary expansion of `b`:

```
a * b = a * (b₀·1 + b₁·x + b₂·x² + ... + b₇·x⁷)
      = b₀·(a) XOR b₁·xtime(a) XOR b₂·xtime²(a) XOR ...
```

In code:

```go
func gmul(a, b byte) byte {
    var p byte
    for i := 0; i < 8; i++ {
        if b&1 != 0 { p ^= a }  // if bit i of b is set, accumulate a·xⁱ
        a = xtime(a)             // a ← a·x
        b >>= 1
    }
    return p
}
```

**Worked example:** `gmul(0x57, 0x13)` where `0x13 = 0001 0011₂` (bits 0, 1, 4 set):
```
0x57·x⁰ = 0x57
0x57·x¹ = xtime(0x57) = 0xAE
0x57·x⁴ = xtime⁴(0x57) = 0x07

gmul(0x57, 0x13) = 0x57 XOR 0xAE XOR 0x07 = 0xFE  ✓
```

---

## The S-Box: Construction from First Principles

The S-box is a bijective (one-to-one, onto) mapping of 256 bytes to 256 bytes. It provides all of AES's non-linearity.

### Step 1: Multiplicative Inverse in GF(2⁸)

For each input byte `a`, compute `a⁻¹` such that `a * a⁻¹ = 1 mod p(x)`.

Special case: `0` has no multiplicative inverse; by convention, `S(0) = 0x63` (0 maps to the affine constant).

For `a ≠ 0`, the inverse can be computed using Fermat's little theorem in GF(2⁸):
```
a⁻¹ = a^(2⁸ - 2) = a^254   (by Fermat: aᵠ = 1, φ = 2⁸-1 = 255)
```

Or equivalently computed via the extended Euclidean algorithm over GF(2).

### Step 2: Affine Transformation over GF(2)

Each bit of the output is computed from 5 bits of the inverse via the affine transformation:

```
b = M · a⁻¹ ⊕ c

Matrix M:
   b₀   [ 1 0 0 0 1 1 1 1 ] [ a₀ ]     [ 1 ]
   b₁   [ 1 1 0 0 0 1 1 1 ] [ a₁ ]     [ 1 ]
   b₂   [ 1 1 1 0 0 0 1 1 ] [ a₂ ]     [ 0 ]
   b₃ = [ 1 1 1 1 0 0 0 1 ] [ a₃ ]  ⊕  [ 0 ]
   b₄   [ 1 1 1 1 1 0 0 0 ] [ a₄ ]     [ 0 ]
   b₅   [ 0 1 1 1 1 1 0 0 ] [ a₅ ]     [ 1 ]
   b₆   [ 0 0 1 1 1 1 1 0 ] [ a₆ ]     [ 1 ]
   b₇   [ 0 0 0 1 1 1 1 1 ] [ a₇ ]     [ 0 ]

c = 0x63 = 0110 0011₂
```

Per-bit formula:
```
bᵢ = aᵢ ⊕ a₍ᵢ₊₄₎ₘₒ₈ ⊕ a₍ᵢ₊₅₎ₘₒ₈ ⊕ a₍ᵢ₊₆₎ₘₒ₈ ⊕ a₍ᵢ₊₇₎ₘₒ₈ ⊕ cᵢ
```

### Why this construction?

- **The multiplicative inverse** provides non-linearity: no linear (or affine) function over GF(2) can approximate the S-box well, making it resistant to linear cryptanalysis.
- **The affine transform** further complicates the algebraic structure (prevents simple algebraic attacks) and removes the "trivial" fixed points that the inverse would otherwise have (e.g., 0x01 → 0x01).
- **The constant 0x63** ensures `S(0) ≠ 0` and `S(1) ≠ 1`.

The result is the **maximum possible non-linearity** (112) for a bijective 8×8 Boolean function. The differential uniformity of 4 is optimal for a power mapping.

---

## The State Matrix

AES loads each 16-byte block into a **4×4 matrix of bytes** called the *state*, stored in **column-major order**:

```
Input bytes:   00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                │  │  │  │
               ┌▼──▼──▼──▼──┐
               │ Col 0     Col 1     Col 2     Col 3 │
   row 0:      │  00         04        08        0c  │
   row 1:      │  01         05        09        0d  │
   row 2:      │  02         06        0a        0e  │
   row 3:      │  03         07        0b        0f  │
               └────────────────────────────────────┘

state[row][col] = bytes[col*4 + row]
```

This column-major ordering matches how AES was designed: MixColumns operates on columns and AddRoundKey keys are stored as column-words.

---

## Round Operations

### AddRoundKey

XOR every state byte with the corresponding byte from the current round key. This is the **only operation that involves the key**.

```go
func addRoundKey(s state, roundKey [][4]byte) state {
    for col := 0; col < 4; col++ {
        for row := 0; row < 4; row++ {
            s[row][col] ^= roundKey[col][row]
        }
    }
    return s
}
```

Because XOR is self-inverse, `AddRoundKey` looks identical in encryption and decryption — just apply it again with the same round key.

**Security role:** Without AddRoundKey, an attacker could analyze the cipher without needing the key. It mixes key material into the state at every round.

---

### SubBytes / InvSubBytes

Replace every byte in the state with its S-box value. Each byte is processed independently — there is no interaction between bytes during SubBytes.

```go
func subBytes(s state) state {
    for row := 0; row < 4; row++ {
        for col := 0; col < 4; col++ {
            s[row][col] = sbox[s[row][col]]
        }
    }
    return s
}
```

**Security role:** The only source of non-linearity in AES. Without SubBytes, AES would be a linear function of the key and plaintext, trivially breakable by solving a system of linear equations.

Decryption uses the **inverse S-box** (constructed by inverting both the affine transform and the multiplicative inverse). `sboxInv[sbox[b]] = b` for all `b`.

---

### ShiftRows / InvShiftRows

Each row `i` of the state is cyclically rotated **left** by `i` byte positions:

```
Row 0 (shift 0):  [a₀, a₁, a₂, a₃] → [a₀, a₁, a₂, a₃]
Row 1 (shift 1):  [b₀, b₁, b₂, b₃] → [b₁, b₂, b₃, b₀]
Row 2 (shift 2):  [c₀, c₁, c₂, c₃] → [c₂, c₃, c₀, c₁]
Row 3 (shift 3):  [d₀, d₁, d₂, d₃] → [d₃, d₀, d₁, d₂]
```

```go
func shiftRows(s state) state {
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
    return s
}
```

**Security role (Wide Trail Strategy):** After ShiftRows, each column of the state contains bytes from **all four original columns**. This means MixColumns in the next round mixes bytes that originated in different columns, producing full inter-column diffusion after just two rounds.

Decryption uses `InvShiftRows` which rotates each row *right* by the same amount.

---

### MixColumns / InvMixColumns

Each column of 4 bytes is treated as a polynomial over GF(2⁸) and multiplied by the fixed polynomial:

```
a(x) = {03}·x³ + {01}·x² + {01}·x + {02}
```

This is equivalent to left-multiplying each column vector by a circulant matrix:

```
⎡ s'₀ ⎤   ⎡ 2  3  1  1 ⎤   ⎡ s₀ ⎤
⎢ s'₁ ⎥ = ⎢ 1  2  3  1 ⎥ × ⎢ s₁ ⎥   (arithmetic in GF(2⁸))
⎢ s'₂ ⎥   ⎢ 1  1  2  3 ⎥   ⎢ s₂ ⎥
⎣ s'₃ ⎦   ⎣ 3  1  1  2 ⎦   ⎣ s₃ ⎦
```

Expanded:
```
s'₀ = gmul(2,s₀) ⊕ gmul(3,s₁) ⊕ s₂          ⊕ s₃
s'₁ = s₀          ⊕ gmul(2,s₁) ⊕ gmul(3,s₂)  ⊕ s₃
s'₂ = s₀          ⊕ s₁          ⊕ gmul(2,s₂)  ⊕ gmul(3,s₃)
s'₃ = gmul(3,s₀)  ⊕ s₁          ⊕ s₂          ⊕ gmul(2,s₃)
```

Since `gmul(3,a) = xtime(a) XOR a`, every computation reduces to `xtime` and `XOR` — fast in hardware and efficient in software.

**Why this matrix?** The `[2,3,1,1]` circulant matrix is an **MDS (Maximum Distance Separable) matrix** over GF(2⁸). MDS means: change any 1 input byte and **all 4 output bytes change**. This is the strongest possible diffusion within a column. Together with ShiftRows, after 2 rounds every output byte depends on every input byte (full avalanche).

**Inverse MixColumns** uses the inverse matrix:

```
⎡ {0e}  {0b}  {0d}  {09} ⎤
⎢ {09}  {0e}  {0b}  {0d} ⎥
⎢ {0d}  {09}  {0e}  {0b} ⎥
⎣ {0b}  {0d}  {09}  {0e} ⎦
```

This uses larger GF(2⁸) multipliers (0x09=9, 0x0b=11, 0x0d=13, 0x0e=14) but the same `gmul` function handles them.

**MixColumns is skipped in the final round.** Omitting it makes the decryption structure symmetric (the inverse is the same operations in reverse without changing the key schedule direction) and provides no security reduction since AddRoundKey follows immediately.

---

## Key Expansion (Key Schedule)

The user key is expanded into `4×(Nr+1)` 32-bit words, grouped into `(Nr+1)` round keys, each 128 bits wide.

### Algorithm (Nk = words in key; Nr = number of rounds)

```
W[0..Nk-1]  ← original key, split into 4-byte words

for i = Nk to 4×(Nr+1)-1:
    temp = W[i-1]
    if i mod Nk == 0:
        temp = SubWord(RotWord(temp)) XOR Rcon[i/Nk]
    else if Nk > 6 and i mod Nk == 4:   // AES-256 only
        temp = SubWord(temp)
    W[i] = W[i-Nk] XOR temp

RoundKey[r] = W[4r .. 4r+3]
```

**RotWord:** rotate a 4-byte word left by one byte: `[a,b,c,d] → [b,c,d,a]`

**SubWord:** apply the S-box to each byte of the word.

**Rcon[j]:** Round constant = `[2^(j-1), 0x00, 0x00, 0x00]` in GF(2⁸).

```
Rcon[1..11] = [01, 02, 04, 08, 10, 20, 40, 80, 1b, 36, 6c]
                └─ successive powers of {02} in GF(2⁸) ─┘
```

### Security of the Key Schedule

- **SubWord** introduces non-linearity, preventing the cipher from degenerating into a linear function even if parts of the key are known.
- **Rcon** ensures that each round key is different even if the original key had a simple structure (e.g., all zeros). Without Rcon, symmetric keys could lead to symmetry in round keys.
- **Key schedule inversion:** Given round key `r`, it's possible to recover all prior round keys — which is why AES keys must remain secret. The key schedule is not designed to be a one-way function.

### AES-128 Example Trace (first 3 words beyond the key)

```
Key: 2b 7e 15 16 | 28 ae d2 a6 | ab f7 15 88 | 09 cf 4f 3c
     W[0]         W[1]           W[2]           W[3]

W[4]: i=4, i mod 4 = 0
  RotWord(W[3]) = cf 4f 3c 09
  SubWord(...)  = 8a 84 eb 01
  XOR Rcon[1]   = 8a^01 84 eb 01 = 8b 84 eb 01
  W[4] = W[0] XOR temp = 2b7e1516 XOR 8b84eb01 = a0 fa fe 17

W[5]: W[1] XOR W[4] = 28aed2a6 XOR a0fafe17 = 88 54 2c b1
W[6]: W[2] XOR W[5] = abf71588 XOR 88542cb1 = 23 a3 39 39
W[7]: W[3] XOR W[6] = 09cf4f3c XOR 23a33939 = 2a 6c 76 05

Round Key 1: a0 fa fe 17  88 54 2c b1  23 a3 39 39  2a 6c 76 05  ✓
```

---

## Full Encryption and Decryption Flow

### Encryption

```
AddRoundKey(state, RoundKey[0])        // initial key whitening

for r = 1 to Nr-1:                     // Nr-1 full rounds
    SubBytes(state)
    ShiftRows(state)
    MixColumns(state)
    AddRoundKey(state, RoundKey[r])

// Final round — MixColumns is omitted
SubBytes(state)
ShiftRows(state)
AddRoundKey(state, RoundKey[Nr])
```

### Decryption

```
AddRoundKey(state, RoundKey[Nr])

for r = Nr-1 downto 1:
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, RoundKey[r])
    InvMixColumns(state)

// Final (first original) round
InvShiftRows(state)
InvSubBytes(state)
AddRoundKey(state, RoundKey[0])
```

Note: Decryption applies InvShiftRows *before* InvSubBytes (unlike the inverse order you might expect) because these two operations commute — they operate on different dimensions (rows vs. individual bytes) so swapping them gives the same result. This "equivalent inverse cipher" structure allows a more efficient implementation.

---

## Security Analysis: Why AES Works

| Property | Provided By | Mechanism |
|---|---|---|
| Confusion | SubBytes | Non-linear S-box prevents algebraic analysis |
| Diffusion (intra-column) | MixColumns | MDS matrix: 1 byte in → 4 bytes out |
| Diffusion (inter-column) | ShiftRows | Bytes spread to different columns before MixColumns |
| Key mixing | AddRoundKey | Every state byte XOR'd with key material each round |
| Brute-force resistance | Key length | 2¹²⁸ or 2²⁵⁶ possible keys |

### Branch Number

The **branch number** of MixColumns is 5: if `d` input bytes differ between two inputs, then at least `5-d` output bytes differ (or more precisely, the minimum total number of differing input+output bytes is 5). This is the maximum possible for a 4×4 byte matrix, following from the MDS property.

After just 2 full AES rounds, every output bit is a complex non-linear function of all 128 input bits and all 128 key bits. The number of active S-boxes over 4 rounds is at least 25 (AES wide-trail argument), making differential and linear cryptanalysis computationally infeasible.

### Best Known Attacks

| Attack | Target | Complexity |
|---|---|---|
| Biclique | AES-128 full | ~2¹²⁶·¹ (4× faster than brute force — impractical) |
| Related-key | AES-256 | 2⁹⁹·⁵ (requires key schedule weakness) |
| Square/Integral | Reduced-round only | Not applicable to full cipher |

The full AES cipher has no practical cryptanalytic attack. AES is considered computationally secure until at least the arrival of sufficiently large quantum computers (Grover's algorithm halves the effective key length to 64/96/128 bits for AES-128/192/256).

---

## Modes of Operation

A mode of operation defines how to use a block cipher to encrypt messages longer than one block. The block cipher provides confidentiality of individual blocks; the mode ensures confidentiality of the overall message.

### ECB — Electronic Codebook ⚠️ INSECURE ⚠️

Each block is encrypted independently with the same key.

```
C[i] = AES_Enc(K, P[i])
P[i] = AES_Dec(K, C[i])
```

**Fatal flaw:** Identical plaintext blocks produce identical ciphertext blocks. The structure of the data is preserved in the ciphertext. The classic demonstration is encrypting an image: the outlines are still visible in the ciphertext. **Never use ECB for real data.**

This implementation includes ECB for demonstration only — specifically to show its weakness.

### CBC — Cipher Block Chaining ✓

Each plaintext block is XOR'd with the previous ciphertext block before encryption. A random **Initialization Vector (IV)** is used for the first block.

```
C[0] = AES_Enc(K, P[0] XOR IV)
C[i] = AES_Enc(K, P[i] XOR C[i-1])

P[0] = AES_Dec(K, C[0]) XOR IV
P[i] = AES_Dec(K, C[i]) XOR C[i-1]
```

This implementation prepends the IV to the ciphertext (`iv || ciphertext`) and generates it randomly using `crypto/rand`.

**Properties:**
- Identical plaintext blocks in the same message produce different ciphertext (assuming a unique IV per message)
- Encryption is sequential (each block depends on the previous ciphertext)
- Decryption is parallelizable
- A corrupted ciphertext block affects exactly 2 plaintext blocks

**IV requirements:** The IV must be **random** (unpredictable) and **unique per encryption** under the same key. It need not be secret — it is transmitted openly with the ciphertext.

### CTR — Counter Mode ✓

A monotonically incrementing counter is encrypted to produce a keystream, which is XOR'd with the plaintext. Encryption and decryption are the same operation.

```
KeyStream[i] = AES_Enc(K, Nonce || Counter[i])
C[i] = P[i] XOR KeyStream[i]
P[i] = C[i] XOR KeyStream[i]
```

This implementation prepends the nonce to the ciphertext and increments the full 16-byte counter as a big-endian integer.

**Properties:**
- No padding required
- Encryption and decryption are the same operation
- Fully parallelizable in both directions
- Supports random access (can decrypt any block without decrypting prior blocks)
- The nonce must **never** be reused with the same key — if nonces are reused, an attacker can XOR two ciphertexts to obtain the XOR of the plaintexts

---

## FIPS 197 Test Vectors

These official vectors from NIST FIPS 197 (Appendix C) are used in the test suite:

### AES-128 (Appendix C.1)
```
Key:    000102030405060708090a0b0c0d0e0f
Input:  00112233445566778899aabbccddeeff
Output: 69c4e0d86a7b0430d8cdb78070b4c55a
```

### AES-192 (Appendix C.2)
```
Key:    000102030405060708090a0b0c0d0e0f1011121314151617
Input:  00112233445566778899aabbccddeeff
Output: dda97ca4864cdfe06eaf70a0ec0d7191
```

### AES-256 (Appendix C.3)
```
Key:    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Input:  00112233445566778899aabbccddeeff
Output: 8ea2b7ca516745bfeafc49904b496089
```

### FIPS 197 Appendix B Trace (AES-128, first 2 rounds)

```
Key:   2b 7e 15 16  28 ae d2 a6  ab f7 15 88  09 cf 4f 3c
Input: 32 43 f6 a8  88 5a 30 8d  31 31 98 a2  e0 37 07 34

Round 0 - AddRoundKey:
  19 3d e3 be  a0 f4 e2 2b  9a c6 8d 2a  e9 f8 48 08

Round 1 - After SubBytes:
  d4 e0 b8 1e  27 bf b4 41  11 98 5d 52  ae f1 e5 30

Round 1 - After ShiftRows:
  d4 e0 b8 1e  bf b4 41 27  5d 52 11 98  30 ae f1 e5

Round 1 - After MixColumns:
  04 e0 48 28  66 cb f8 06  81 19 d3 26  e5 9a 7a 4c

Round 1 - After AddRoundKey (RK1 = a0 fa fe 17  88 54 2c b1  23 a3 39 39  2a 6c 76 05):
  a4 68 6b 02  9c 9f 5b 6a  7f 35 ea 50  f2 2b 43 49

Final ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
```

---

## Project Layout

```
aes-from-scratch/
├── aes/
│   ├── aes.go          # Core cipher: state, S-boxes, GF(2⁸), all round ops, key schedule
│   ├── modes.go        # ECB, CBC, CTR + PKCS#7 padding utilities
│   └── aes_test.go     # FIPS 197 known-answer tests + round-trip tests for all modes
├── main.go             # Demo: FIPS 197 vector, CBC/CTR/ECB with all three key sizes
├── visualization.html  # Interactive browser visualization (open this!)
├── go.mod
└── README.md
```

---

## Running the Code

```bash
# Run the demonstration
go run .

# Run all tests (FIPS 197 official test vectors + round-trip tests)
go test ./aes/ -v

# Run a specific test
go test ./aes/ -run TestAES128BlockEncrypt -v
```

Expected test output:
```
=== RUN   TestAES128BlockEncrypt
--- PASS: TestAES128BlockEncrypt (0.00s)
=== RUN   TestAES192BlockEncrypt
--- PASS: TestAES192BlockEncrypt (0.00s)
=== RUN   TestAES256BlockEncrypt
--- PASS: TestAES256BlockEncrypt (0.00s)
=== RUN   TestAES128BlockDecrypt
--- PASS: TestAES128BlockDecrypt (0.00s)
=== RUN   TestRoundTrip
--- PASS: TestRoundTrip (0.00s)
=== RUN   TestGmul
--- PASS: TestGmul (0.00s)
PASS
ok      aes-from-scratch/aes    0.002s
```

---

## API Reference

```go
import "aes-from-scratch/aes"

// Create a cipher — key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes
c, err := aes.NewCipher(key)

// Single 16-byte block, in-place
err = c.Encrypt(block)  // block []byte, len=16
err = c.Decrypt(block)

// ECB mode — INSECURE, for demonstration only
ciphertext, err := c.ECBEncrypt(plaintext)
plaintext,  err := c.ECBDecrypt(ciphertext)

// CBC mode — prepends random IV to ciphertext output
ciphertext, err := c.CBCEncrypt(plaintext)         // returns iv || ciphertext
plaintext,  err := c.CBCDecrypt(ciphertext)         // expects iv || ciphertext

// CTR mode — prepends nonce to ciphertext output
ciphertext, err := c.CTRCrypt(plaintext,  true)    // encrypt: returns nonce || ciphertext
plaintext,  err := c.CTRCrypt(ciphertext, false)   // decrypt: expects nonce || ciphertext
```

---

## Security Notice

This implementation is for **educational purposes**. It has two important limitations for production use:

1. **Not constant-time.** The S-box lookups and table accesses are data-dependent. On hardware with cache-timing side channels, an attacker with local access may be able to extract key material via timing measurements (cache-timing attack / Flush+Reload). Go's standard `crypto/aes` uses hardware AES-NI instructions on supported CPUs, which are both faster and constant-time.

2. **Not audited.** This code has not undergone a professional cryptographic security audit.

For production cryptography, use Go's `crypto/aes` (block cipher) with `crypto/cipher` (modes), or a higher-level library like `golang.org/x/crypto`.
