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
//!
//! ## Cross-implementation contract (Rust ↔ C)
//!
//! The Rust node owns the wire format at the consensus boundary. The C
//! library (`noble-tx-core`) used by Apple-side and WRY clients is a
//! mirror — same byte output, separate implementation. These vectors
//! are the **bridge contract** that asserts the two stay byte-identical
//! for the covered code paths.
//!
//! **Coverage gap (tracked):** today the vectors exercise coinbase + fee
//! distribution + a few notarization shapes. They do NOT exhaustively
//! cover every tx type × every optional-field combination. Drift on
//! uncovered paths would only be caught by end-to-end client-to-node
//! testing, not at CI time. Expanding coverage to every tx type is a
//! follow-up.

use crate::WireFormat;
use noble_core::address::NobleAddress;
use noble_core::block::BlockHeader;
use noble_core::metadata::MetadataEntry;
use noble_core::transaction::Transaction;
use noble_core::utxo::{OutPoint, TxIn, TxOut};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope, SCHEME_SECP256K1};

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

pub const VEC_PUBKEY_SECP256K1: &str =
    "582202024242424242424242424242424242424242424242424242424242424242424242";

pub const VEC_SIG_ENVELOPE: &str =
    "5863022102bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

pub const VEC_COINBASE_TX: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff6a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01";

pub const VEC_BLOCK_HEADER: &str =
    "a866686569676874016b6d65726b6c655f726f6f745820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6f707265765f626c6f636b5f68617368582000000000000000000000000000000000000000000000000000000000000000006974696d657374616d701a6553f1006874785f636f756e74016c76616c696461746f725f69645822020242424242424242424242424242424242424242424242424242424242424242426d76616c696461746f725f73696758630221024242424242424242424242424242424242424242424242424242424242424242000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006776657273696f6e01";

pub const VEC_TX_SIGNING_PAYLOAD: &str =
    "a868636861696e5f69641a8c9fe96968636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006f696e7075745f6f7574706f696e747381a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff686d6574616461746180676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01";

// Generated on 2026-03-24 from noble-wire v0.91.0.
// Platform: aarch64-apple-darwin (Apple Silicon).
// NEVER EDIT THESE.

pub const VEC_TRANSFER_TX: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64766f7574006a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747382a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a055d4a80a267616464726573735822020355555555555555555555555555555555555555555555555555555555555555556576616c75651a008954406974696d657374616d701a6553f1006774785f74797065016776657273696f6e01";

pub const VEC_NOTARIZE_TX: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd66696e7075747381a16b707265765f6f7574707574a264747869645820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb64766f7574016a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746182a2636b657968646f635f747970656576616c7565467265706f7274a2636b657966617574686f726576616c75654a4e6f626c65204c616273676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05e69ec06974696d657374616d701a6553f1006774785f74797065006776657273696f6e01";

pub const VEC_TX_WITH_GATEWAY: &str =
    "aa6f6164646974696f6e616c5f736967738068636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006f676174657761795f61646472657373582102777777777777777777777777777777777777777777777777777777777777777766696e7075747381a16b707265765f6f7574707574a264747869645820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64766f7574006a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747382a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a055d4a80a267616464726573735822020355555555555555555555555555555555555555555555555555555555555555556576616c75651a008954406974696d657374616d701a6553f1006774785f74797065016776657273696f6e01";

pub const VEC_TX_WITH_EXPIRY: &str =
    "aa6f6164646974696f6e616c5f736967738068636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006a657870697265735f61741a6555428066696e7075747381a16b707265765f6f7574707574a264747869645820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64766f7574006a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747382a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a055d4a80a267616464726573735822020355555555555555555555555555555555555555555555555555555555555555556576616c75651a008954406974696d657374616d701a6553f1006774785f74797065016776657273696f6e01";

pub const VEC_TX_WITH_ADDITIONAL_SIG: &str =
    "a96f6164646974696f6e616c5f73696773815863022102bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc68636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64766f7574006a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747382a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a055d4a80a267616464726573735822020355555555555555555555555555555555555555555555555555555555555555556576616c75651a008954406974696d657374616d701a6553f1006774785f74797065016776657273696f6e01";

pub const VEC_FEE_DIST_TX: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff6a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a004c4b406974696d657374616d701a6553f1006774785f74797065116776657273696f6e01";

pub const VEC_TX_SIGNING_TRANSFER: &str =
    "a868636861696e5f69641a8c9fe96968636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006f696e7075745f6f7574706f696e747381a264747869645820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64766f757400686d6574616461746180676f75747075747382a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a055d4a80a267616464726573735822020355555555555555555555555555555555555555555555555555555555555555556576616c75651a008954406974696d657374616d701a6553f1006774785f74797065016776657273696f6e01";

pub const VEC_TX_MULTI_METADATA: &str =
    "a96f6164646974696f6e616c5f736967738068636865636b73756d5820dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd66696e7075747381a16b707265765f6f7574707574a264747869645820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb64766f7574016a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746183a2636b6579667a5f6c6173746576616c7565457468697264a2636b657966617574686f726576616c7565456669727374a2636b6579666d6964646c656576616c7565467365636f6e64676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05e69ec06974696d657374616d701a6553f1006774785f74797065006776657273696f6e01";

pub const VEC_HDR_SIGNING_PAYLOAD: &str =
    "a766686569676874016b6d65726b6c655f726f6f745820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6f707265765f626c6f636b5f68617368582000000000000000000000000000000000000000000000000000000000000000006974696d657374616d701a6553f1006874785f636f756e74016c76616c696461746f725f69645822020242424242424242424242424242424242424242424242424242424242424242426776657273696f6e01";

// ── Test fixture builders ───────────────────────────────────────────────

fn make_test_pubkey() -> NoblePublicKey {
    NoblePublicKey::Secp256k1(vec![0x02; 1].into_iter().chain(vec![0x42; 32]).collect())
}

fn make_test_sig() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme_id: SCHEME_SECP256K1,
        public_key: vec![0x02; 1].into_iter().chain(vec![0x42; 32]).collect(),
        signature: vec![0x00; 64],
    }
}

fn make_test_sig_bb() -> SignatureEnvelope {
    SignatureEnvelope {
        scheme_id: SCHEME_SECP256K1,
        public_key: vec![0x02; 1].into_iter().chain(vec![0xBB; 32]).collect(),
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
        issuer_sig: make_test_sig(),
        additional_sigs: vec![],
        declared_cosigners: Vec::new(),
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
            expires_at: None,
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

fn make_second_pubkey() -> NoblePublicKey {
    NoblePublicKey::Secp256k1(vec![0x03; 1].into_iter().chain(vec![0x55; 32]).collect())
}

fn make_transfer_tx() -> Transaction {
    Transaction {
        version: 1,
        tx_type: 0x01, // transfer
        inputs: vec![TxIn {
            prev_output: OutPoint { txid: Hash256::from_bytes([0xAA; 32]), vout: 0 },
        }],
        outputs: vec![
            TxOut { value: 90_000_000, address: NobleAddress::Noble(make_test_pubkey()) },
            TxOut { value: 9_000_000, address: NobleAddress::Noble(make_second_pubkey()) },
        ],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: make_test_sig(),
        additional_sigs: vec![],
        declared_cosigners: Vec::new(),
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    }
}

fn make_notarize_tx() -> Transaction {
    Transaction {
        version: 1,
        tx_type: 0x00, // notarization
        inputs: vec![TxIn {
            prev_output: OutPoint { txid: Hash256::from_bytes([0xBB; 32]), vout: 1 },
        }],
        outputs: vec![
            TxOut { value: 99_000_000, address: NobleAddress::Noble(make_test_pubkey()) },
        ],
        checksum: Hash256::from_bytes([0xDD; 32]),
        timestamp: 1_700_000_000,
        issuer_sig: make_test_sig(),
        additional_sigs: vec![],
        declared_cosigners: Vec::new(),
        metadata: vec![
            MetadataEntry { key: "doc_type".into(), value: b"report".to_vec() },
            MetadataEntry { key: "author".into(), value: b"Noble Labs".to_vec() },
        ],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    }
}

fn make_tx_with_gateway() -> Transaction {
    let mut tx = make_transfer_tx();
    tx.gateway_address = Some(vec![0x02; 1].into_iter().chain(vec![0x77; 32]).collect());
    tx
}

fn make_tx_with_expiry() -> Transaction {
    let mut tx = make_transfer_tx();
    tx.expires_at = Some(1_700_086_400); // +1 day
    tx
}

fn make_tx_with_additional_sig() -> Transaction {
    let mut tx = make_transfer_tx();
    tx.additional_sigs = vec![make_test_sig_bb()];
    tx
}

fn make_fee_dist_tx() -> Transaction {
    Transaction {
        version: 1,
        tx_type: 0x11, // fee distribution
        inputs: vec![TxIn {
            prev_output: OutPoint::COINBASE_PREVOUT,
        }],
        outputs: vec![
            TxOut { value: 5_000_000, address: NobleAddress::Noble(make_test_pubkey()) },
        ],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: make_test_sig(),
        additional_sigs: vec![],
        declared_cosigners: Vec::new(),
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    }
}

fn make_multi_metadata_tx() -> Transaction {
    let mut tx = make_notarize_tx();
    tx.metadata = vec![
        MetadataEntry { key: "z_last".into(), value: b"third".to_vec() },
        MetadataEntry { key: "author".into(), value: b"first".to_vec() },
        MetadataEntry { key: "middle".into(), value: b"second".to_vec() },
    ];
    tx
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
        ("NoblePublicKey::Secp256k1", make_test_pubkey().wire_bytes(), VEC_PUBKEY_SECP256K1),
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
        ("Transaction (transfer)", make_transfer_tx().wire_bytes(), VEC_TRANSFER_TX),
        ("Transaction (notarize)", make_notarize_tx().wire_bytes(), VEC_NOTARIZE_TX),
        ("Transaction (gateway)", make_tx_with_gateway().wire_bytes(), VEC_TX_WITH_GATEWAY),
        ("Transaction (expiry)", make_tx_with_expiry().wire_bytes(), VEC_TX_WITH_EXPIRY),
        ("Transaction (additional_sig)", make_tx_with_additional_sig().wire_bytes(), VEC_TX_WITH_ADDITIONAL_SIG),
        ("Transaction (fee_dist)", make_fee_dist_tx().wire_bytes(), VEC_FEE_DIST_TX),
        (
            "TxSigningPayload (transfer)",
            crate::v1::tx_signing_payload_bytes(&make_transfer_tx(), 0x8C9FE969),
            VEC_TX_SIGNING_TRANSFER,
        ),
        ("Transaction (multi_metadata)", make_multi_metadata_tx().wire_bytes(), VEC_TX_MULTI_METADATA),
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
    fn frozen_pubkey_secp256k1() {
        assert_eq!(hex::encode(make_test_pubkey().wire_bytes()), VEC_PUBKEY_SECP256K1);
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

    #[test]
    fn frozen_transfer_tx() {
        assert_eq!(hex::encode(make_transfer_tx().wire_bytes()), VEC_TRANSFER_TX);
    }

    #[test]
    fn frozen_notarize_tx() {
        assert_eq!(hex::encode(make_notarize_tx().wire_bytes()), VEC_NOTARIZE_TX);
    }

    #[test]
    fn frozen_tx_with_gateway() {
        assert_eq!(hex::encode(make_tx_with_gateway().wire_bytes()), VEC_TX_WITH_GATEWAY);
    }

    #[test]
    fn frozen_tx_with_expiry() {
        assert_eq!(hex::encode(make_tx_with_expiry().wire_bytes()), VEC_TX_WITH_EXPIRY);
    }

    #[test]
    fn frozen_tx_with_additional_sig() {
        assert_eq!(hex::encode(make_tx_with_additional_sig().wire_bytes()), VEC_TX_WITH_ADDITIONAL_SIG);
    }

    #[test]
    fn frozen_fee_dist_tx() {
        assert_eq!(hex::encode(make_fee_dist_tx().wire_bytes()), VEC_FEE_DIST_TX);
    }

    #[test]
    fn frozen_tx_signing_transfer() {
        let bytes = crate::v1::tx_signing_payload_bytes(&make_transfer_tx(), 0x8C9FE969);
        assert_eq!(hex::encode(bytes), VEC_TX_SIGNING_TRANSFER);
    }

    #[test]
    fn frozen_tx_multi_metadata() {
        assert_eq!(hex::encode(make_multi_metadata_tx().wire_bytes()), VEC_TX_MULTI_METADATA);
    }

    // ── Cross-encoder tx_id comparison ───────────────────────────────────
    //
    // C and Rust use DIFFERENT CBOR formats for transport (serde vs wire),
    // but both compute tx_id using the SAME wire format internally.
    // These tests verify that C's tx_id matches Rust's for the same tx.

    fn derive_address_hex(privkey_hex: &str) -> String {
        let sk_bytes = hex::decode(privkey_hex).unwrap();
        let hash = noble_crypto::sha256(&sk_bytes);
        let (_, pk) = noble_crypto::secp256k1::keypair_from_secret(
            hash.as_bytes(),
        ).expect("keypair_from_secret failed");
        let pubkey = NoblePublicKey::Secp256k1(pk);
        let addr = NobleAddress::Noble(pubkey);
        hex::encode(addr.to_wire_bytes())
    }

    /// Cross-encoder: C and Rust compute same tx_id for coinbase.
    #[test]
    fn cross_encoder_coinbase_txid() {
        let privkey_hex = "aa".repeat(32);
        let addr_hex = derive_address_hex(&privkey_hex);
        let json = serde_json::json!({
            "private_key": privkey_hex,
            "validator_address": addr_hex,
            "subsidy_amount": 10_000_000_000u64,
            "chain_id": 0x4E4F424Cu32,
            "timestamp": 1_700_000_000u64,
        });
        let result_str = noble_tx_core::build_coinbase(&json.to_string())
            .expect("C build_coinbase failed");
        let result: serde_json::Value = serde_json::from_str(&result_str).unwrap();
        let c_txid = result["tx_id"].as_str().expect("missing tx_id");
        let tx_hex = result["tx_hex"].as_str().expect("missing tx_hex");
        let c_bytes = hex::decode(tx_hex).unwrap();

        let tx: Transaction = noble_codec::cbor_de::from_cbor(&c_bytes)
            .expect("failed to decode C CBOR");
        let rust_txid = hex::encode(tx.compute_tx_id(0x4E4F424C).unwrap().as_bytes());

        assert_eq!(c_txid, rust_txid,
            "coinbase tx_id divergence:\n  C:    {c_txid}\n  Rust: {rust_txid}");
    }

    /// Cross-encoder: C and Rust compute same tx_id for fee distribution.
    #[test]
    fn cross_encoder_fee_dist_txid() {
        let privkey_hex = "aa".repeat(32);
        let addr_hex = derive_address_hex(&privkey_hex);
        let json = serde_json::json!({
            "private_key": privkey_hex,
            "chain_id": 0x4E4F424Cu32,
            "timestamp": 1_700_000_000u64,
            "outputs": [{"value": 5_000_000u64, "address": addr_hex}],
        });
        let result_str = noble_tx_core::build_fee_distribution(&json.to_string())
            .expect("C build_fee_distribution failed");
        let result: serde_json::Value = serde_json::from_str(&result_str).unwrap();
        let c_txid = result["tx_id"].as_str().expect("missing tx_id");
        let tx_hex = result["tx_hex"].as_str().expect("missing tx_hex");
        let c_bytes = hex::decode(tx_hex).unwrap();

        let tx: Transaction = noble_codec::cbor_de::from_cbor(&c_bytes)
            .expect("failed to decode C CBOR");
        let rust_txid = hex::encode(tx.compute_tx_id(0x4E4F424C).unwrap().as_bytes());

        assert_eq!(c_txid, rust_txid,
            "fee_dist tx_id divergence:\n  C:    {c_txid}\n  Rust: {rust_txid}");
    }
}
