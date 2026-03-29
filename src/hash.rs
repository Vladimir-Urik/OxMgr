use sha2::{Digest, Sha256};

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}
