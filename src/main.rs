// XTEA (eXtended Tiny Encryption Algorithm)
// Block size: 64 bits (two u32)
// Key size:   128 bits (four u32)
// Rounds:     32 cycles (each cycle = 2 Feistel rounds)

const DELTA: u32 = 0x9E37_79B9;
const NUM_ROUNDS: u32 = 32;

fn encrypt_block(block: &mut [u32; 2], key: &[u32; 4]) {
    let (mut v0, mut v1) = (block[0], block[1]);
    let mut sum: u32 = 0;
    for _ in 0..NUM_ROUNDS {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ sum.wrapping_add(key[(sum & 3) as usize]),
        );
        sum = sum.wrapping_add(DELTA);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(key[((sum >> 11) & 3) as usize]),
        );
    }
    block[0] = v0;
    block[1] = v1;
}

fn decrypt_block(block: &mut [u32; 2], key: &[u32; 4]) {
    let (mut v0, mut v1) = (block[0], block[1]);
    let mut sum: u32 = DELTA.wrapping_mul(NUM_ROUNDS);
    for _ in 0..NUM_ROUNDS {
        v1 = v1.wrapping_sub(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(key[((sum >> 11) & 3) as usize]),
        );
        sum = sum.wrapping_sub(DELTA);
        v0 = v0.wrapping_sub(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ sum.wrapping_add(key[(sum & 3) as usize]),
        );
    }
    block[0] = v0;
    block[1] = v1;
}

fn bytes_to_block(bytes: &[u8; 8]) -> [u32; 2] {
    [
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    ]
}

fn block_to_bytes(block: &[u32; 2]) -> [u8; 8] {
    let a = block[0].to_be_bytes();
    let b = block[1].to_be_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let key: [u32; 4] = [0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210];
    let plaintext: [u8; 8] = *b"HelloXTE";

    let mut block = bytes_to_block(&plaintext);
    println!(
        "Key:        {:08x} {:08x} {:08x} {:08x}",
        key[0], key[1], key[2], key[3]
    );
    println!(
        "Plaintext:  {} ({:?})",
        hex(&plaintext),
        std::str::from_utf8(&plaintext).unwrap()
    );

    encrypt_block(&mut block, &key);
    let ciphertext = block_to_bytes(&block);
    println!("Ciphertext: {}", hex(&ciphertext));

    decrypt_block(&mut block, &key);
    let recovered = block_to_bytes(&block);
    println!(
        "Decrypted:  {} ({:?})",
        hex(&recovered),
        std::str::from_utf8(&recovered).unwrap()
    );

    assert_eq!(recovered, plaintext, "round-trip failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn run_vector(key_hex: &str, pt_hex: &str, ct_hex: &str) {
        let key_bytes = hex_to_bytes(key_hex);
        let pt_bytes = hex_to_bytes(pt_hex);
        let ct_bytes = hex_to_bytes(ct_hex);

        let key: [u32; 4] = [
            u32::from_be_bytes(key_bytes[0..4].try_into().unwrap()),
            u32::from_be_bytes(key_bytes[4..8].try_into().unwrap()),
            u32::from_be_bytes(key_bytes[8..12].try_into().unwrap()),
            u32::from_be_bytes(key_bytes[12..16].try_into().unwrap()),
        ];
        let pt: [u8; 8] = pt_bytes.try_into().unwrap();
        let ct: [u8; 8] = ct_bytes.try_into().unwrap();

        let mut block = bytes_to_block(&pt);
        encrypt_block(&mut block, &key);
        assert_eq!(block_to_bytes(&block), ct, "encrypt mismatch");

        decrypt_block(&mut block, &key);
        assert_eq!(block_to_bytes(&block), pt, "decrypt mismatch");
    }

    // Published XTEA test vectors (32 cycles).
    #[test]
    fn vector_all_zero() {
        run_vector(
            "00000000000000000000000000000000",
            "0000000000000000",
            "dee9d4d8f7131ed9",
        );
    }

    #[test]
    fn vector_classic() {
        run_vector(
            "000102030405060708090a0b0c0d0e0f",
            "4142434445464748",
            "497df3d072612cb5",
        );
    }

    #[test]
    fn round_trip() {
        let key = [0xdead_beef_u32, 0xfeed_face, 0xcafe_babe, 0x1337_c0de];
        let original = [0x1234_5678_u32, 0x9abc_def0];
        let mut block = original;
        encrypt_block(&mut block, &key);
        assert_ne!(block, original, "ciphertext should differ from plaintext");
        decrypt_block(&mut block, &key);
        assert_eq!(block, original);
    }
}
