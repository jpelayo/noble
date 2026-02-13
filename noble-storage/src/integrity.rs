// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Periodic chain integrity verification.

use noble_core::compute_merkle_root;
use noble_crypto::Hash256;

use crate::traits::StorageEngine;

/// The kind of integrity finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    /// The stored block hash does not match recomputation.
    BlockHashMismatch,
    /// The merkle root in the header does not match the transactions.
    MerkleRootMismatch,
    /// A height is missing from the chain (gap).
    HeightGap,
    /// The prev_block_hash does not point to the previous height's hash.
    PrevHashMismatch,
}

/// A single integrity finding.
#[derive(Debug, Clone)]
pub struct IntegrityFinding {
    pub height: u64,
    pub kind: FindingKind,
    pub detail: String,
}

/// Summary of an integrity scan.
#[derive(Debug)]
pub struct IntegrityReport {
    /// Number of heights checked.
    pub heights_checked: u64,
    /// First corrupt height found, if any.
    pub first_corrupt_height: Option<u64>,
    /// All findings.
    pub findings: Vec<IntegrityFinding>,
}

impl IntegrityReport {
    /// Whether the scanned range is clean.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Verify chain integrity over the range [start, end] inclusive.
///
/// Checks:
/// 1. Block exists at each height (no gaps)
/// 2. Block hash recomputation matches stored hash
/// 3. Merkle root recomputation matches header
/// 4. prev_block_hash linkage is correct
pub fn verify_chain_integrity(
    storage: &dyn StorageEngine,
    chain_id: u32,
    start: u64,
    end: u64,
) -> IntegrityReport {
    let mut report = IntegrityReport {
        heights_checked: 0,
        first_corrupt_height: None,
        findings: Vec::new(),
    };

    let mut prev_hash: Option<Hash256> = if start > 0 {
        // Load the block at start-1 to get its hash for linkage check
        storage.get_block_hash_by_height(start - 1).ok()
    } else {
        Some(Hash256::ZERO)
    };

    for height in start..=end {
        report.heights_checked += 1;

        // Check 1: block exists
        let stored_hash = match storage.get_block_hash_by_height(height) {
            Ok(h) => h,
            Err(_) => {
                add_finding(
                    &mut report,
                    height,
                    FindingKind::HeightGap,
                    format!("no block at height {height}"),
                );
                prev_hash = None;
                continue;
            }
        };

        let block = match storage.get_block(&stored_hash) {
            Ok(b) => b,
            Err(_) => {
                add_finding(
                    &mut report,
                    height,
                    FindingKind::HeightGap,
                    format!("block hash exists but block data missing at height {height}"),
                );
                prev_hash = None;
                continue;
            }
        };

        // Check 2: block hash recomputation
        if let Ok(recomputed) = block.header.compute_block_hash() {
            if recomputed != stored_hash {
                add_finding(
                    &mut report,
                    height,
                    FindingKind::BlockHashMismatch,
                    format!("stored={stored_hash}, recomputed={recomputed}"),
                );
            }
        }

        // Check 3: merkle root
        let tx_ids: Vec<Hash256> = block
            .transactions
            .iter()
            .filter_map(|tx| tx.compute_tx_id(chain_id).ok())
            .collect();
        let recomputed_merkle = compute_merkle_root(&tx_ids);
        if recomputed_merkle != block.header.merkle_root {
            add_finding(
                &mut report,
                height,
                FindingKind::MerkleRootMismatch,
                format!(
                    "header={}, recomputed={recomputed_merkle}",
                    block.header.merkle_root
                ),
            );
        }

        // Check 4: prev_block_hash linkage
        if let Some(expected_prev) = prev_hash {
            if block.header.prev_block_hash != expected_prev {
                add_finding(
                    &mut report,
                    height,
                    FindingKind::PrevHashMismatch,
                    format!(
                        "expected prev={expected_prev}, got {}",
                        block.header.prev_block_hash
                    ),
                );
            }
        }

        prev_hash = Some(stored_hash);
    }

    report
}

fn add_finding(report: &mut IntegrityReport, height: u64, kind: FindingKind, detail: String) {
    if report.first_corrupt_height.is_none() {
        report.first_corrupt_height = Some(height);
    }
    report.findings.push(IntegrityFinding {
        height,
        kind,
        detail,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use noble_core::{Block, BlockHeader, MAINNET_CHAIN_ID, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

    fn make_block(
        height: u64,
        prev_hash: Hash256,
        val_sk: &[u8],
        val_pk: &[u8],
    ) -> (Block, Hash256, Vec<Hash256>) {
        let val_priv = NoblePrivateKey::Ed25519(val_sk.to_vec());
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 1_700_000_000 + height,
            height,
            tx_count: 0,
            validator_id: val_pub,
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: val_pk.to_vec(),
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();
        let hash = header.compute_block_hash().unwrap();
        (
            Block {
                header,
                transactions: vec![],
            },
            hash,
            vec![],
        )
    }

    #[test]
    fn integrity_clean_chain() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (b0, h0, ids0) = make_block(0, Hash256::ZERO, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();
        let (b1, h1, ids1) = make_block(1, h0, &sk, &pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let report = verify_chain_integrity(&store, MAINNET_CHAIN_ID, 0, 1);
        assert!(report.is_clean());
        assert_eq!(report.heights_checked, 2);
        assert!(report.first_corrupt_height.is_none());
    }

    #[test]
    fn integrity_detects_height_gap() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (b0, h0, ids0) = make_block(0, Hash256::ZERO, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();
        // Skip height 1, commit height 2 (would need to force this)
        // Instead, just scan a range that includes a missing height
        let report = verify_chain_integrity(&store, MAINNET_CHAIN_ID, 0, 2);
        assert!(!report.is_clean());
        assert_eq!(report.first_corrupt_height, Some(1));
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::HeightGap));
    }

    #[test]
    fn integrity_report_empty_range() {
        let store = MemoryStorage::new();
        // Scan range with no blocks
        let report = verify_chain_integrity(&store, MAINNET_CHAIN_ID, 0, 0);
        assert!(!report.is_clean()); // height 0 doesn't exist
    }

    #[test]
    fn integrity_single_block() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (b0, h0, ids0) = make_block(0, Hash256::ZERO, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        let report = verify_chain_integrity(&store, MAINNET_CHAIN_ID, 0, 0);
        assert!(report.is_clean());
        assert_eq!(report.heights_checked, 1);
    }
}
