// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree computation and inclusion proofs for NOBLE blocks.

use serde::{Deserialize, Serialize};

use noble_crypto::{sha256, Hash256};

/// Compute the Merkle root from a list of transaction IDs.
///
/// - Empty list: SHA-256 of 32 zero bytes
/// - Single item: the item itself
/// - Odd count: duplicate the last item
/// - Pairs are hashed as `sha256(left || right)`
pub fn compute_merkle_root(tx_ids: &[Hash256]) -> Hash256 {
    if tx_ids.is_empty() {
        return sha256(&[0u8; 32]);
    }
    if tx_ids.len() == 1 {
        return tx_ids[0];
    }

    let mut level: Vec<Hash256> = tx_ids.to_vec();

    while level.len() > 1 {
        // If odd number, duplicate the last element
        if level.len() % 2 != 0 {
            level.push(*level.last().unwrap());
        }

        let mut next_level = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks_exact(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(chunk[0].as_bytes());
            combined[32..].copy_from_slice(chunk[1].as_bytes());
            next_level.push(sha256(&combined));
        }
        level = next_level;
    }

    level[0]
}

/// Direction of a sibling in a Merkle proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofDirection {
    /// Sibling is on the left: `sha256(sibling || current)`.
    Left,
    /// Sibling is on the right: `sha256(current || sibling)`.
    Right,
}

/// A single step in a Merkle proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    /// The sibling hash at this tree level.
    pub hash: Hash256,
    /// Position of the sibling relative to the current node.
    pub direction: ProofDirection,
}

/// A Merkle inclusion proof with block context (GAP-M9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The transaction ID being proved.
    pub tx_id: Hash256,
    /// Block hash for context (GAP-M9).
    pub block_hash: Hash256,
    /// Block height for context (GAP-M9).
    pub block_height: u64,
    /// Index of the transaction in the block.
    pub tx_index: usize,
    /// Path from the leaf to the root.
    pub path: Vec<ProofStep>,
}

impl MerkleProof {
    /// Generate a Merkle proof for the transaction at `index` within `tx_ids`.
    pub fn generate(
        tx_ids: &[Hash256],
        index: usize,
        block_hash: Hash256,
        block_height: u64,
    ) -> Result<Self, String> {
        if tx_ids.is_empty() {
            return Err("cannot generate proof for empty tree".to_string());
        }
        if index >= tx_ids.len() {
            return Err(format!(
                "index {} out of range (tree has {} leaves)",
                index,
                tx_ids.len()
            ));
        }

        let tx_id = tx_ids[index];
        let mut path = Vec::new();
        let mut level: Vec<Hash256> = tx_ids.to_vec();
        let mut current_index = index;

        while level.len() > 1 {
            if level.len() % 2 != 0 {
                level.push(*level.last().unwrap());
            }

            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let direction = if current_index % 2 == 0 {
                ProofDirection::Right
            } else {
                ProofDirection::Left
            };

            path.push(ProofStep {
                hash: level[sibling_index],
                direction,
            });

            // Compute next level
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks_exact(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(chunk[0].as_bytes());
                combined[32..].copy_from_slice(chunk[1].as_bytes());
                next_level.push(sha256(&combined));
            }

            current_index /= 2;
            level = next_level;
        }

        Ok(Self {
            tx_id,
            block_hash,
            block_height,
            tx_index: index,
            path,
        })
    }

    /// Verify this proof against an expected Merkle root.
    pub fn verify(&self, expected_root: &Hash256) -> Result<(), String> {
        let mut current = self.tx_id;

        for step in &self.path {
            let mut combined = [0u8; 64];
            match step.direction {
                ProofDirection::Left => {
                    combined[..32].copy_from_slice(step.hash.as_bytes());
                    combined[32..].copy_from_slice(current.as_bytes());
                }
                ProofDirection::Right => {
                    combined[..32].copy_from_slice(current.as_bytes());
                    combined[32..].copy_from_slice(step.hash.as_bytes());
                }
            }
            current = sha256(&combined);
        }

        if current == *expected_root {
            Ok(())
        } else {
            Err(format!(
                "proof verification failed: computed {} != expected {}",
                current, expected_root
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hashes(n: usize) -> Vec<Hash256> {
        (0..n).map(|i| sha256(&(i as u64).to_be_bytes())).collect()
    }

    // --- compute_merkle_root ---

    #[test]
    fn merkle_root_empty() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, sha256(&[0u8; 32]));
    }

    #[test]
    fn merkle_root_single() {
        let h = sha256(b"only one");
        let root = compute_merkle_root(&[h]);
        assert_eq!(root, h);
    }

    #[test]
    fn merkle_root_two() {
        let a = sha256(b"tx0");
        let b = sha256(b"tx1");
        let root = compute_merkle_root(&[a, b]);

        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(a.as_bytes());
        combined[32..].copy_from_slice(b.as_bytes());
        let expected = sha256(&combined);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_three_duplicates_last() {
        let ids = make_hashes(3);
        let root = compute_merkle_root(&ids);

        // With 3 items, last is duplicated to make 4
        let a = ids[0];
        let b = ids[1];
        let c = ids[2];
        let d = ids[2]; // duplicate

        let ab = sha256(&[a.0, b.0].concat());
        let cd = sha256(&[c.0, d.0].concat());
        let expected = sha256(&[ab.0, cd.0].concat());
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_deterministic() {
        let ids = make_hashes(7);
        let r1 = compute_merkle_root(&ids);
        let r2 = compute_merkle_root(&ids);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_order_matters() {
        let a = sha256(b"first");
        let b = sha256(b"second");
        let root_ab = compute_merkle_root(&[a, b]);
        let root_ba = compute_merkle_root(&[b, a]);
        assert_ne!(root_ab, root_ba);
    }

    // --- MerkleProof ---

    #[test]
    fn proof_single_element() {
        let ids = make_hashes(1);
        let root = compute_merkle_root(&ids);
        let proof = MerkleProof::generate(&ids, 0, Hash256::ZERO, 1).unwrap();
        assert!(proof.path.is_empty());
        assert!(proof.verify(&root).is_ok());
    }

    #[test]
    fn proof_two_elements() {
        let ids = make_hashes(2);
        let root = compute_merkle_root(&ids);
        for i in 0..2 {
            let proof = MerkleProof::generate(&ids, i, Hash256::ZERO, 1).unwrap();
            assert!(proof.verify(&root).is_ok());
        }
    }

    #[test]
    fn proof_three_elements() {
        let ids = make_hashes(3);
        let root = compute_merkle_root(&ids);
        for i in 0..3 {
            let proof = MerkleProof::generate(&ids, i, Hash256::ZERO, 1).unwrap();
            assert!(proof.verify(&root).is_ok(), "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_seven_elements() {
        let ids = make_hashes(7);
        let root = compute_merkle_root(&ids);
        for i in 0..7 {
            let proof = MerkleProof::generate(&ids, i, Hash256::ZERO, 1).unwrap();
            assert!(proof.verify(&root).is_ok(), "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_100_elements() {
        let ids = make_hashes(100);
        let root = compute_merkle_root(&ids);
        for i in [0, 1, 49, 50, 98, 99] {
            let proof = MerkleProof::generate(&ids, i, Hash256::ZERO, 1).unwrap();
            assert!(proof.verify(&root).is_ok(), "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_1000_elements() {
        let ids = make_hashes(1000);
        let root = compute_merkle_root(&ids);
        for i in [0, 1, 499, 500, 998, 999] {
            let proof = MerkleProof::generate(&ids, i, Hash256::ZERO, 1).unwrap();
            assert!(proof.verify(&root).is_ok(), "proof failed for index {i}");
        }
    }

    #[test]
    fn proof_context_fields_present() {
        let ids = make_hashes(5);
        let block_hash = sha256(b"block");
        let proof = MerkleProof::generate(&ids, 2, block_hash, 42).unwrap();
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.block_height, 42);
        assert_eq!(proof.tx_index, 2);
    }

    #[test]
    fn tampered_proof_rejected() {
        let ids = make_hashes(8);
        let root = compute_merkle_root(&ids);
        let mut proof = MerkleProof::generate(&ids, 3, Hash256::ZERO, 1).unwrap();

        // Tamper with the proof
        if let Some(step) = proof.path.first_mut() {
            step.hash = Hash256::ZERO;
        }
        assert!(proof.verify(&root).is_err());
    }

    #[test]
    fn wrong_root_rejected() {
        let ids = make_hashes(4);
        let proof = MerkleProof::generate(&ids, 0, Hash256::ZERO, 1).unwrap();
        let wrong_root = Hash256::from_bytes([0xFF; 32]);
        assert!(proof.verify(&wrong_root).is_err());
    }

    #[test]
    fn proof_empty_tree_error() {
        assert!(MerkleProof::generate(&[], 0, Hash256::ZERO, 0).is_err());
    }

    #[test]
    fn proof_out_of_range_error() {
        let ids = make_hashes(3);
        assert!(MerkleProof::generate(&ids, 5, Hash256::ZERO, 0).is_err());
    }

    #[test]
    fn proof_cbor_roundtrip() {
        use noble_codec::NobleCbor;
        let ids = make_hashes(4);
        let proof = MerkleProof::generate(&ids, 1, sha256(b"block"), 10).unwrap();
        let bytes = proof.to_cbor().unwrap();
        let decoded = MerkleProof::from_cbor(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
