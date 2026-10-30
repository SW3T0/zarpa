// SPDX-License-Identifier: Apache-2.0
//! Transfer manifest and the receiver-side set of verified blocks.

use crate::block::hash_block;
use std::ops::Range;

/// Describes a file as a list of fixed-size blocks and their BLAKE3 hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub block_size: usize,
    pub hashes: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn from_bytes(data: &[u8], block_size: usize) -> Self {
        assert!(block_size > 0, "block_size must be positive");
        Self {
            size: data.len() as u64,
            block_size,
            hashes: data.chunks(block_size).map(hash_block).collect(),
        }
    }

    pub fn block_count(&self) -> usize {
        self.hashes.len()
    }

    /// Byte range of block `index` inside the file, or `None` if out of range.
    pub fn block_range(&self, index: usize) -> Option<Range<usize>> {
        if index >= self.hashes.len() {
            return None;
        }
        let start = index * self.block_size;
        let end = (start + self.block_size).min(self.size as usize);
        Some(start..end)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block index out of range")]
    OutOfRange,
    #[error("block hash mismatch")]
    HashMismatch,
}

/// Receiver-side record of which blocks have been received AND verified.
#[derive(Debug, Clone)]
pub struct VerifiedSet {
    manifest: Manifest,
    have: Vec<bool>,
}

impl VerifiedSet {
    pub fn new(manifest: Manifest) -> Self {
        let n = manifest.block_count();
        Self { manifest, have: vec![false; n] }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Verifies `data` against the manifest hash and marks the block as present.
    pub fn accept(&mut self, index: usize, data: &[u8]) -> Result<(), BlockError> {
        let expected = self.manifest.hashes.get(index).ok_or(BlockError::OutOfRange)?;
        if hash_block(data) != *expected {
            return Err(BlockError::HashMismatch);
        }
        self.have[index] = true;
        Ok(())
    }

    /// Indices of blocks not yet verified.
    pub fn missing(&self) -> Vec<u32> {
        self.have
            .iter()
            .enumerate()
            .filter(|(_, h)| !**h)
            .map(|(i, _)| i as u32)
            .collect()
    }

    pub fn verified_count(&self) -> usize {
        self.have.iter().filter(|h| **h).count()
    }

    pub fn is_complete(&self) -> bool {
        self.have.iter().all(|h| *h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::gen_bytes;

    #[test]
    fn manifest_counts_blocks_and_ranges() {
        let m = Manifest::from_bytes(&gen_bytes(1, 10), 4);
        assert_eq!(m.block_count(), 3);
        assert_eq!(m.block_range(0), Some(0..4));
        assert_eq!(m.block_range(2), Some(8..10));
        assert_eq!(m.block_range(3), None);
    }

    #[test]
    fn verified_set_accepts_good_block_and_rejects_bad() {
        let data = gen_bytes(2, 8);
        let mut set = VerifiedSet::new(Manifest::from_bytes(&data, 4));
        assert_eq!(set.missing(), vec![0, 1]);
        assert_eq!(set.accept(0, &data[0..4]), Ok(()));
        assert_eq!(set.accept(1, b"nope"), Err(BlockError::HashMismatch));
        assert_eq!(set.accept(9, &data[0..4]), Err(BlockError::OutOfRange));
        assert_eq!(set.missing(), vec![1]);
        assert_eq!(set.verified_count(), 1);
        assert!(!set.is_complete());
        assert_eq!(set.accept(1, &data[4..8]), Ok(()));
        assert!(set.is_complete());
    }

    #[test]
    fn empty_file_is_complete_with_zero_blocks() {
        let set = VerifiedSet::new(Manifest::from_bytes(&[], 4));
        assert_eq!(set.manifest().block_count(), 0);
        assert!(set.is_complete());
    }
}
