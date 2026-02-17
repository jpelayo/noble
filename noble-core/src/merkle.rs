// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Merkle tree computation and inclusion proofs for NOBLE blocks.

use serde::{Deserialize, Serialize};

use noble_crypto::{sha256, Hash256};

use crate::constants::{MERKLE_INTERNAL_PREFIX, MERKLE_LEAF_PREFIX};

/// Hash a leaf node with domain-separation prefix (C-merkle).
/// `sha256(0x00 || tx_id)`
fn hash_leaf(tx_id: &Hash256) -> Hash256 {
    let mut buf = [0u8; 33];
    buf[0] = MERKLE_LEAF_PREFIX;
    buf[1..33].copy_from_slice(tx_id.as_bytes());
    sha256(&buf)
}

/// Hash an internal node with domain-separation prefix (C-merkle).
/// `sha256(0x01 || left || right)`
fn hash_internal(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = [0u8; 65];
    buf[0] = MERKLE_INTERNAL_PREFIX;
    buf[1..33].copy_from_slice(left.as_bytes());
    buf[33..65].copy_from_slice(right.as_bytes());
    sha256(&buf)
}

/// Compute the Merkle root from a list of transaction IDs.
///
/// Uses domain-separated hashing (C-merkle):
/// - Leaf nodes: `sha256(0x00 || tx_id)`
/// - Internal nodes: `sha256(0x01 || left || right)`
/// - Empty list: SHA-256 of 32 zero bytes
/// - Single item: hash_leaf(item)
/// - Odd count: duplicate the last item
#[tracing::instrument(skip(tx_ids), fields(task = "merkle", count = tx_ids.len()))]
pub fn compute_merkle_root(tx_ids: &[Hash256]) -> Hash256 {
    if tx_ids.is_empty() {
        tracing::trace!("merkle: empty tree, returning hash of zeros");
        return sha256(&[0u8; 32]);
    }

    // Hash all leaves with domain-separation prefix
    let mut level: Vec<Hash256> = tx_ids.iter().map(hash_leaf).collect();

    if level.len() == 1 {
        tracing::trace!("merkle: single leaf, returning leaf hash");
        return level[0];
    }

    let mut tree_level: usize = 0;
    while level.len() > 1 {
        // If odd number, duplicate the last element
        if level.len() % 2 != 0 {
            level.push(*level.last().unwrap());
        }

        let mut next_level = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks_exact(2) {
            next_level.push(hash_internal(&chunk[0], &chunk[1]));
        }
        tracing::trace!(level = tree_level, nodes = level.len(), "merkle level {}: {} nodes", tree_level, level.len());
        tree_level += 1;
        level = next_level;
    }

    tracing::trace!("merkle root computed");
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
        // Hash all leaves with domain-separation
        let mut level: Vec<Hash256> = tx_ids.iter().map(hash_leaf).collect();
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

            // Compute next level with domain-separated internal hashing
            let mut next_level = Vec::with_capacity(level.len() / 2);
            for chunk in level.chunks_exact(2) {
                next_level.push(hash_internal(&chunk[0], &chunk[1]));
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
        // Start with the leaf hash (domain-separated)
        let mut current = hash_leaf(&self.tx_id);

        for step in &self.path {
            // Internal nodes use domain-separated hashing
            current = match step.direction {
                ProofDirection::Left => hash_internal(&step.hash, &current),
                ProofDirection::Right => hash_internal(&current, &step.hash),
            };
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
        // Single leaf is domain-separated: sha256(0x00 || tx_id)
        assert_eq!(root, hash_leaf(&h));
    }

    #[test]
    fn merkle_root_two() {
        let a = sha256(b"tx0");
        let b = sha256(b"tx1");
        let root = compute_merkle_root(&[a, b]);

        // Domain-separated: hash_internal(hash_leaf(a), hash_leaf(b))
        let la = hash_leaf(&a);
        let lb = hash_leaf(&b);
        let expected = hash_internal(&la, &lb);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_three_duplicates_last() {
        let ids = make_hashes(3);
        let root = compute_merkle_root(&ids);

        // With 3 items, last leaf hash is duplicated to make 4
        let la = hash_leaf(&ids[0]);
        let lb = hash_leaf(&ids[1]);
        let lc = hash_leaf(&ids[2]);
        let ld = lc; // duplicate

        let ab = hash_internal(&la, &lb);
        let cd = hash_internal(&lc, &ld);
        let expected = hash_internal(&ab, &cd);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_domain_separation_prevents_leaf_internal_collision() {
        // C-merkle: domain separation prevents second preimage attacks.
        // A leaf hash sha256(0x00 || data) must never collide with
        // an internal hash sha256(0x01 || left || right).
        let tx_id = sha256(b"test tx");
        let leaf = hash_leaf(&tx_id);
        let internal = hash_internal(&tx_id, &Hash256::ZERO);
        assert_ne!(leaf, internal, "leaf and internal hashes must differ");
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
