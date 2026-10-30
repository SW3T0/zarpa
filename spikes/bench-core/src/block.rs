// SPDX-License-Identifier: Apache-2.0
//! Block size, hashing and deterministic test payloads.

/// Block size used by the spike (4 MiB), as in `docs/protocol/README.md`.
pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Deterministic pseudo-random bytes (xorshift64*), so tests and benchmarks need no files.
pub fn gen_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// BLAKE3 hash of one block.
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_bytes_is_deterministic_and_exact_length() {
        let a = gen_bytes(7, 1000);
        let b = gen_bytes(7, 1000);
        assert_eq!(a, b);
        assert_eq!(a.len(), 1000);
    }

    #[test]
    fn gen_bytes_differs_by_seed() {
        assert_ne!(gen_bytes(1, 64), gen_bytes(2, 64));
    }

    #[test]
    fn gen_bytes_zero_seed_is_valid() {
        assert_eq!(gen_bytes(0, 16).len(), 16);
        assert_ne!(gen_bytes(0, 16), vec![0u8; 16]);
    }

    #[test]
    fn hash_block_differs_for_different_data() {
        assert_ne!(hash_block(b"a"), hash_block(b"b"));
    }
}
