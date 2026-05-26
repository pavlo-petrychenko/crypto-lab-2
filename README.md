## How it works

Split the 64-bit input into two 32-bit halves, `v0` and `v1`. Then run 32 cycles. Each cycle nudges `v0` using `v1`, and then nudges `v1` using the new `v0`.

The nudge looks like this:

```
v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])
sum += DELTA
v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])
```
## Running it

```sh
cargo run     # encrypts "HelloXTE", prints hex, decrypts back
cargo test    # checks against published test vectors
```
