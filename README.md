# XTEA

A Rust implementation of XTEA — a tiny block cipher from 1997 by Wheeler and Needham. It encrypts 64-bit blocks with a 128-bit key, and the whole thing fits in a handful of lines.

## How it works

You split the 64-bit input into two 32-bit halves, `v0` and `v1`. Then you run 32 cycles. Each cycle nudges `v0` using `v1`, and then nudges `v1` using the new `v0` — a classic Feistel network.

The nudge looks like this:

```
v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])
sum += DELTA
v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])
```

A few things going on here:

The shifts and XOR (`(v1 << 4) ^ (v1 >> 5)`) smear the bits around so flipping one bit of the input affects lots of bits of the output. Then `+ v1` mixes the smeared version back with the original. So far that's pure diffusion — no key involved yet.

The key gets mixed in on the right side: `sum + key[...]`. The `sum` is a counter that grows by `DELTA = 0x9E3779B9` (a constant pulled from the golden ratio) every cycle, so each round uses a different value. And the index `sum & 3` picks one of the four key words — which word changes from round to round in a hard-to-predict way. This shuffled key schedule is the main thing XTEA fixed over its predecessor TEA, which had related-key attacks.

Then those two pieces — the diffused `v1` and the keyed `sum` — get XORed together and added into `v0`. That's one half of a cycle. The second half does the same thing in reverse, updating `v1` using `v0`.

The reason it's secure despite being so small: it mixes three operations from different math worlds — shifts, XOR, and addition mod 2³². None of them alone would resist analysis, but combined they're surprisingly hard to untangle.

Decryption is the same structure backwards. You start `sum` at its final value (`DELTA * 32`) and subtract instead of add. XOR is its own inverse, and subtraction undoes the addition, so you get your plaintext back.

## Running it

```sh
cargo run     # encrypts "HelloXTE", prints hex, decrypts back
cargo test    # checks against published test vectors
```
