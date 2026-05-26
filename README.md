# XTEA (eXtended Tiny Encryption Algorithm)

A Rust implementation of the XTEA block cipher, written for educational purposes as part of a cryptography lab.

## What is XTEA?

**XTEA** is a symmetric-key block cipher designed in 1997 by David Wheeler and Roger Needham at the Cambridge Computer Laboratory. It was created to fix weaknesses found in their earlier **TEA** cipher (related-key and equivalent-key attacks).

It is famous for being **extremely small** — the entire algorithm fits in a few lines of code — while still being reasonably secure. This makes it popular for embedded systems, microcontrollers, and other resource-constrained environments where AES is too heavy.

## Parameters

| Property | Value |
|---|---|
| Block size | **64 bits** (two 32-bit words: `v0`, `v1`) |
| Key size | **128 bits** (four 32-bit words: `k[0..3]`) |
| Structure | Feistel network |
| Rounds | **32 cycles** (each cycle = 2 Feistel half-rounds, so 64 rounds total) |
| Delta constant | `0x9E3779B9` — derived from the golden ratio: ⌊2³² / φ⌋ |

## How the algorithm works

### 1. The big picture

XTEA is a **Feistel cipher**. The 64-bit plaintext block is split into two 32-bit halves, `v0` and `v1`. In every cycle, each half is updated by mixing it with the other half, a running counter (`sum`), and one of the four 32-bit subkeys. After 32 cycles the two halves form the ciphertext.

Decryption runs the same structure in reverse, starting `sum` at its final value and subtracting instead of adding.

### 2. The core mixing operation

The trick that makes XTEA secure despite being so simple is the **mixing of three different algebraic operations**:

- **Shifts** (`<<`, `>>`) — linear over GF(2)
- **XOR** (`^`) — addition mod 2 (linear over GF(2))
- **Addition mod 2³²** (`+`) — NOT linear over GF(2)

Mixing operations from different algebraic groups is what makes the cipher non-linear and hard to break. None of them alone would be secure, but combined they are.

### 3. The round function

In each of the 32 cycles, XTEA does two updates — one for `v0`, one for `v1`:

```
v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])
sum += DELTA
v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])
```

Let's break the inner expression down:

| Piece | Purpose |
|---|---|
| `(v << 4) ^ (v >> 5)` | Diffusion — spreads bits around so a single bit flip in the input affects many bits of the output |
| `+ v` | Adds the unshifted value back in, mixing original and diffused versions |
| `sum + key[...]` | Injects the round-dependent key material |
| Outer `^` | Combines the diffusion result with the key material |
| Outer `+=` | Adds the result back into the half being updated (the Feistel step) |

### 4. The key schedule

XTEA does **not** expand the key into separate round subkeys (this is where it's "tiny"). Instead, each round picks one of the four key words on the fly, using bits of `sum`:

- For `v0`'s update: `key[sum & 3]` — uses the lowest 2 bits of `sum`
- For `v1`'s update: `key[(sum >> 11) & 3]` — uses bits 11–12 of `sum`

Because `sum` changes each cycle (it accumulates `DELTA = 0x9E3779B9`), the subkey index cycles through all four keys in an irregular pattern. **This shuffled key schedule is the main fix over the original TEA**, which had a much more predictable schedule and was vulnerable to related-key attacks.

### 5. Decryption

Decryption is symmetric — start `sum` at `DELTA * 32` (its value at the end of encryption) and unwind:

```
v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])
sum -= DELTA
v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])
```

Subtracting reverses the additions; XOR is its own inverse. Because Feistel networks are inherently invertible, the round function doesn't need to be invertible itself — only the surrounding `+=` / `-=` step needs to be undone.

### 6. Why 32 cycles?

Cryptanalysis shows that reduced-round variants (e.g., 8 or 16 cycles) are breakable. At 32 cycles XTEA is considered to have no practically faster attack than brute force on the 128-bit key.

## Implementation notes (Rust)

A few Rust-specific details in this implementation:

- **`wrapping_add` / `wrapping_sub`** — XTEA's spec is arithmetic mod 2³². Rust panics on `u32` overflow in debug builds, so we must use the wrapping methods explicitly.
- **`DELTA: u32 = 0x9E37_79B9`** — the constant.
- **Big-endian byte ↔ word conversion** — when converting an 8-byte block to two `u32`s, we use big-endian (`from_be_bytes`). XTEA's spec doesn't fix an endianness, but big-endian is by far the most common convention used in published test vectors.

## Project layout

```
.
├── Cargo.toml
├── GOAL.md           # original lab task: "Implement XTEA"
├── README.md         # this file
└── src/
    └── main.rs       # encrypt_block, decrypt_block, demo, tests
```

## Running

```sh
cargo run      # encrypts the string "HelloXTE", prints hex, decrypts it back
cargo test     # validates against published XTEA test vectors
```

### Sample output

```
Key:        01234567 89abcdef fedcba98 76543210
Plaintext:  48656c6c6f585445 ("HelloXTE")
Ciphertext: 9d06e1bc0478272b
Decrypted:  48656c6c6f585445 ("HelloXTE")
```

### Test vectors

The test suite validates the implementation against two canonical published XTEA vectors:

| Key | Plaintext | Ciphertext |
|---|---|---|
| `00...00` (128 zero bits) | `0000000000000000` | `dee9d4d8f7131ed9` |
| `000102030405060708090a0b0c0d0e0f` | `4142434445464748` (`"ABCDEFGH"`) | `497df3d072612cb5` |

Plus a round-trip test with pseudo-random key and plaintext.

## Security note

XTEA is interesting historically and pedagogically, and is still used in some legacy and embedded contexts, but it is **not recommended for new production systems**. Its 64-bit block size makes it vulnerable to birthday-bound attacks (e.g., Sweet32) when encrypting large amounts of data under one key. For modern use, prefer **AES** with a proper mode (GCM, ChaCha20-Poly1305).

A successor cipher, **XXTEA** (1998), was also proposed by Wheeler and Needham, with a variable-length block and stronger diffusion.

## References

- D. Wheeler, R. Needham, *"Tea extensions"*, Technical report, Cambridge University, 1997.
- [Wikipedia: XTEA](https://en.wikipedia.org/wiki/XTEA)
