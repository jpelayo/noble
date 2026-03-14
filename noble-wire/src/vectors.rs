// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Frozen test vectors for Wire Format V1.
//!
//! These vectors define the exact byte output for known inputs. They are
//! the canonical reference — if any code change causes a vector mismatch,
//! ALL existing block hashes, transaction IDs, and signatures are invalidated.
//!
//! NEVER modify these hex strings. If the encoding must change, create V2.
//!
//! These vectors are verified by:
//! - `cargo test -p noble-wire` (CI)
//! - `noble-tool verify-wire` (runtime, brew post_install)

use crate::WireFormat;
use noble_core::address::NobleAddress;
use noble_core::block::BlockHeader;
use noble_core::transaction::Transaction;
use noble_core::utxo::{OutPoint, TxIn, TxOut};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope, SCHEME_ED25519};

/// A single frozen test vector.
pub struct FrozenVector {
    pub name: &'static str,
    pub expected_hex: &'static str,
}

// ── Frozen hex constants ────────────────────────────────────────────────
// Generated on 2026-03-14 from noble-wire v0.42.0.
// Platform: aarch64-apple-darwin (Apple Silicon).
// NEVER EDIT THESE.

pub const VEC_HASH256_ZERO: &str =
    "58200000000000000000000000000000000000000000000000000000000000000000";

pub const VEC_OUTPOINT_COINBASE: &str =
    "a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff";

pub const VEC_PUBKEY_ED25519: &str =
    "5821014242424242424242424242424242424242424242424242424242424242424242";

pub const VEC_SIG_ENVELOPE: &str =
    "58620120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub const VEC_COINBASE_TX: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff686d6574616461746180676f75747075747381a2676164647265737358210142424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006d7075626c69736865725f736967586201204242424242424242424242424242424242424242424242424242424242424242000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01";

pub const VEC_BLOCK_HEADER: &str =
    "a866686569676874016b6d65726b6c655f726f6f745820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6f707265765f626c6f636b5f68617368582000000000000000000000000000000000000000000000000000000000000000006974696d657374616d701a6553f1006874785f636f756e74016c76616c696461746f725f696458210142424242424242424242424242424242424242424242424242424242424242426d76616c696461746f725f736967586201204242424242424242424242424242424242424242424242424242424242424242000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006776657273696f6e01";

pub const VEC_TX_SIGNING_PAYLOAD: &str =
    "a868636861696e5f69641a8c9fe96968636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006f696e7075745f6f7574706f696e747381a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff686d6574616461746180676f75747075747381a2676164647265737358210142424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01";

pub const VEC_HDR_SIGNING_PAYLOAD: &str =
    "a766686569676874016b6d65726b6c655f726f6f745820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6f707265765f626c6f636b5f68617368582000000000000000000000000000000000000000000000000000000000000000006974696d657374616d701a6553f1006874785f636f756e74016c76616c696461746f725f696458210142424242424242424242424242424242424242424242424242424242424242426776657273696f6e01";

// ── Test fixture builders ───────────────────────────────────────────────

fn make_test_pubkey() -> NoblePublicKey {
    NoblePublicKey::Ed25519(vec![0x42; 32])
}

fn make_test_sig() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme_id: SCHEME_ED25519,
        public_key: vec![0x42; 32],
        signature: vec![0x00; 64],
    }
}

fn make_test_sig_bb() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme_id: SCHEME_ED25519,
        public_key: vec![0xBB; 32],
        signature: vec![0xCC; 64],
    }
}

fn make_coinbase_tx() -> Transaction {
    Transaction {
        version: 1,
        tx_type: 0x10,
        inputs: vec![TxIn {
            prev_output: OutPoint::COINBASE_PREVOUT,
        }],
        outputs: vec![TxOut {
            value: 100_000_000,
            address: NobleAddress::Noble(make_test_pubkey()),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        publisher_sig: make_test_sig(),
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
    }
}

fn make_block_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: Hash256::ZERO,
        merkle_root: Hash256::from_bytes([0xFF; 32]),
        timestamp: 1_700_000_000,
        height: 1,
        tx_count: 1,
        validator_id: make_test_pubkey(),
        validator_sig: make_test_sig(),
    }
}

// ── Public verification function ────────────────────────────────────────

/// Result of a single vector check.
pub struct VectorResult {
    pub name: &'static str,
    pub pass: bool,
    pub expected_len: usize,
    pub actual_len: usize,
}

/// Verify all frozen test vectors. Returns results for each vector.
///
/// Called by `noble-tool verify-wire` and `brew post_install`.
/// If any vector fails, the binary's wire format is inconsistent
/// with the protocol spec — blocks and transactions will be rejected
/// by other nodes.
pub fn verify_all_vectors() -> Vec<VectorResult> {
    let checks: Vec<(&str, Vec<u8>, &str)> = vec![
        ("Hash256::ZERO", Hash256::ZERO.wire_bytes(), VEC_HASH256_ZERO),
        ("OutPoint::COINBASE", OutPoint::COINBASE_PREVOUT.wire_bytes(), VEC_OUTPOINT_COINBASE),
        ("NoblePublicKey::Ed25519", make_test_pubkey().wire_bytes(), VEC_PUBKEY_ED25519),
        ("SignatureEnvelope", make_test_sig_bb().wire_bytes(), VEC_SIG_ENVELOPE),
        ("Transaction (coinbase)", make_coinbase_tx().wire_bytes(), VEC_COINBASE_TX),
        ("BlockHeader", make_block_header().wire_bytes(), VEC_BLOCK_HEADER),
        (
            "TxSigningPayload",
            crate::v1::tx_signing_payload_bytes(&make_coinbase_tx(), 0x8C9FE969),
            VEC_TX_SIGNING_PAYLOAD,
        ),
        (
            "HeaderSigningPayload",
            crate::v1::header_signing_payload_bytes(&make_block_header()),
            VEC_HDR_SIGNING_PAYLOAD,
        ),
    ];

    checks
        .into_iter()
        .map(|(name, actual_bytes, expected_hex)| {
            let actual_hex = hex::encode(&actual_bytes);
            VectorResult {
                name,
                pass: actual_hex == expected_hex,
                expected_len: expected_hex.len() / 2,
                actual_len: actual_bytes.len(),
            }
        })
        .collect()
}

// ── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_hash256_zero() {
        assert_eq!(hex::encode(Hash256::ZERO.wire_bytes()), VEC_HASH256_ZERO);
    }

    #[test]
    fn frozen_outpoint_coinbase() {
        assert_eq!(
            hex::encode(OutPoint::COINBASE_PREVOUT.wire_bytes()),
            VEC_OUTPOINT_COINBASE
        );
    }

    #[test]
    fn frozen_pubkey_ed25519() {
        assert_eq!(hex::encode(make_test_pubkey().wire_bytes()), VEC_PUBKEY_ED25519);
    }

    #[test]
    fn frozen_sig_envelope() {
        assert_eq!(hex::encode(make_test_sig_bb().wire_bytes()), VEC_SIG_ENVELOPE);
    }

    #[test]
    fn frozen_coinbase_tx() {
        assert_eq!(hex::encode(make_coinbase_tx().wire_bytes()), VEC_COINBASE_TX);
    }

    #[test]
    fn frozen_block_header() {
        assert_eq!(hex::encode(make_block_header().wire_bytes()), VEC_BLOCK_HEADER);
    }

    #[test]
    fn frozen_tx_signing_payload() {
        let bytes = crate::v1::tx_signing_payload_bytes(&make_coinbase_tx(), 0x8C9FE969);
        assert_eq!(hex::encode(bytes), VEC_TX_SIGNING_PAYLOAD);
    }

    #[test]
    fn frozen_hdr_signing_payload() {
        let bytes = crate::v1::header_signing_payload_bytes(&make_block_header());
        assert_eq!(hex::encode(bytes), VEC_HDR_SIGNING_PAYLOAD);
    }

    #[test]
    fn verify_all_passes() {
        let results = verify_all_vectors();
        for r in &results {
            assert!(r.pass, "FROZEN VECTOR MISMATCH: {} (expected {} bytes, got {})", r.name, r.expected_len, r.actual_len);
        }
    }
}
