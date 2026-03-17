// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Property-based tests for NOBLE core types using proptest.
//!
//! Verifies fundamental invariants over 10,000+ random inputs:
//! 1. CBOR roundtrip: from_cbor(to_cbor(x)) == x
//! 2. Canonical idempotency: canonical(decode(canonical(x))) == canonical(x)
//! 3. tx_id determinism: same tx → same tx_id

use noble_codec::NobleCbor;
use noble_core::{MetadataEntry, OutPoint, Transaction, TxIn, TxOut};
use noble_core::genesis::{build_genesis, derive_chain_id, GENESIS_TIMESTAMP};

fn test_chain_id() -> u32 {
    use std::sync::LazyLock;
    static ID: LazyLock<u32> = LazyLock::new(|| {
        let block = build_genesis(GENESIS_TIMESTAMP, b"noble-test-genesis");
        let hash = block.header.compute_block_hash().unwrap();
        derive_chain_id(&hash)
    });
    *ID
}
use noble_crypto::{
    ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_ED25519,
};
use proptest::prelude::*;

// --- Strategies ---

fn arb_hash256() -> impl Strategy<Value = Hash256> {
    prop::array::uniform32(any::<u8>()).prop_map(Hash256::from_bytes)
}

fn arb_metadata_entry() -> impl Strategy<Value = MetadataEntry> {
    (
        "[a-z]{1,16}",                              // key: 1-16 ASCII lowercase chars
        prop::collection::vec(any::<u8>(), 1..=32), // value: 1-32 bytes
    )
        .prop_map(|(key, value)| MetadataEntry { key, value })
}

fn arb_signature_envelope() -> impl Strategy<Value = SignatureEnvelope> {
    (
        prop::collection::vec(any::<u8>(), 32..=32), // public_key
        prop::collection::vec(any::<u8>(), 64..=64), // signature
    )
        .prop_map(|(public_key, signature)| SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key,
            signature,
        })
}

fn arb_transaction() -> impl Strategy<Value = Transaction> {
    (
        arb_hash256(),                                          // checksum
        1_600_000_000u64..1_800_000_000u64,                     // timestamp
        arb_hash256(),                                          // input txid
        arb_signature_envelope(),                               // issuer_sig
        prop::collection::vec(arb_signature_envelope(), 0..=3), // additional_sigs
        prop::collection::vec(arb_metadata_entry(), 0..=4),     // metadata
    )
        .prop_map(
            |(checksum, timestamp, input_txid, issuer_sig, additional_sigs, metadata)| Transaction {
                version: 1,
                tx_type: 0,
                inputs: vec![TxIn {
                    prev_output: OutPoint { txid: input_txid, vout: 0 },
                }],
                outputs: vec![],
                checksum,
                timestamp,
                issuer_sig,
                additional_sigs,
                metadata,
                encrypted_locator: None,
                external_attestations: vec![],
                gateway_address: None,
        contract_data: None,
            },
        )
}

// --- Property: Hash256 CBOR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn hash256_roundtrip(hash in arb_hash256()) {
        let bytes = hash.to_cbor().unwrap();
        let decoded = Hash256::from_cbor(&bytes).unwrap();
        prop_assert_eq!(hash, decoded);
    }
}

// --- Property: Hash256 canonical idempotency ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn hash256_canonical_idempotent(hash in arb_hash256()) {
        let canonical1 = hash.canonical_bytes().unwrap();
        let decoded = Hash256::from_cbor(&canonical1).unwrap();
        let canonical2 = decoded.canonical_bytes().unwrap();
        prop_assert_eq!(canonical1, canonical2);
    }
}

// --- Property: MetadataEntry CBOR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn metadata_entry_roundtrip(entry in arb_metadata_entry()) {
        let bytes = entry.to_cbor().unwrap();
        let decoded = MetadataEntry::from_cbor(&bytes).unwrap();
        prop_assert_eq!(entry, decoded);
    }
}

// --- Property: MetadataEntry canonical idempotency ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn metadata_entry_canonical_idempotent(entry in arb_metadata_entry()) {
        let canonical1 = entry.canonical_bytes().unwrap();
        let decoded = MetadataEntry::from_cbor(&canonical1).unwrap();
        let canonical2 = decoded.canonical_bytes().unwrap();
        prop_assert_eq!(canonical1, canonical2);
    }
}

// --- Property: SignatureEnvelope CBOR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn signature_envelope_roundtrip(env in arb_signature_envelope()) {
        let bytes = env.to_cbor().unwrap();
        let decoded = SignatureEnvelope::from_cbor(&bytes).unwrap();
        prop_assert_eq!(env, decoded);
    }
}

// --- Property: Transaction CBOR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn transaction_roundtrip(tx in arb_transaction()) {
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        prop_assert_eq!(tx, decoded);
    }
}

// --- Property: Transaction canonical idempotency ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn transaction_canonical_idempotent(tx in arb_transaction()) {
        let canonical1 = tx.canonical_bytes().unwrap();
        let decoded = Transaction::from_cbor(&canonical1).unwrap();
        let canonical2 = decoded.canonical_bytes().unwrap();
        prop_assert_eq!(canonical1, canonical2);
    }
}

// --- Property: tx_id determinism ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn tx_id_deterministic(tx in arb_transaction()) {
        let id1 = tx.compute_tx_id(test_chain_id()).unwrap();
        let id2 = tx.compute_tx_id(test_chain_id()).unwrap();
        prop_assert_eq!(id1, id2);
    }
}

// --- Property: signing message determinism ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn signing_message_deterministic(tx in arb_transaction()) {
        let msg1 = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let msg2 = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        prop_assert_eq!(msg1, msg2);
    }
}

// --- Strategy: transfer transaction ---

fn arb_transfer_transaction() -> impl Strategy<Value = Transaction> {
    (
        1_600_000_000u64..1_800_000_000u64, // timestamp
        1u64..1_000_000u64,                 // amount (> 0)
        arb_hash256(),                      // input txid
        arb_signature_envelope(),           // issuer_sig
        prop::collection::vec(arb_signature_envelope(), 0..=3), // additional_sigs
        prop::collection::vec(arb_metadata_entry(), 0..=4), // metadata
        prop::collection::vec(any::<u8>(), 32..=32), // recipient key bytes
    )
        .prop_map(
            |(
                timestamp,
                amount,
                input_txid,
                issuer_sig,
                additional_sigs,
                metadata,
                recipient_bytes,
            )| {
                Transaction {
                    version: 1,
                    tx_type: 1,
                    inputs: vec![TxIn {
                        prev_output: OutPoint { txid: input_txid, vout: 0 },
                    }],
                    outputs: vec![TxOut {
                        value: amount,
                        address: noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(recipient_bytes)),
                    }],
                    checksum: Hash256::ZERO,
                    timestamp,
                    issuer_sig,
                    additional_sigs,
                    metadata,
                    encrypted_locator: None,
                    external_attestations: vec![],
                    gateway_address: None,
        contract_data: None,
                }
            },
        )
}

// --- Property: Transfer transaction CBOR roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn transfer_tx_roundtrip(tx in arb_transfer_transaction()) {
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        prop_assert_eq!(tx, decoded);
    }
}

// --- Property: real signed transaction roundtrip with valid signatures ---

#[test]
fn signed_transaction_roundtrip_100() {
    let (sk, pk) = ed25519::generate_keypair();
    let (_, recipient_pk) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk);

    for i in 0..100u64 {
        let is_transfer = i >= 70; // ~30 transfer transactions
        let checksum = if is_transfer {
            Hash256::ZERO
        } else {
            sha256(&i.to_be_bytes())
        };
        let outputs = if is_transfer {
            vec![TxOut {
                value: 1_000 * i + 1,
                address: noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(recipient_pk.clone())),
            }]
        } else {
            vec![]
        };
        let mut tx = Transaction {
            version: 1,
            tx_type: if is_transfer { 1 } else { 0 },
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: sha256(&i.to_le_bytes()), vout: 0 },
            }],
            outputs,
            checksum,
            timestamp: 1_700_000_000 + i,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };

        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        // Roundtrip through CBOR
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        assert_eq!(tx, decoded);

        // Canonical roundtrip
        let canonical = tx.canonical_bytes().unwrap();
        let decoded2 = Transaction::from_cbor(&canonical).unwrap();
        assert_eq!(tx, decoded2);

        // tx_id determinism
        let id1 = tx.compute_tx_id(test_chain_id()).unwrap();
        let id2 = decoded.compute_tx_id(test_chain_id()).unwrap();
        assert_eq!(id1, id2);
    }
}

// --- Property: signing message includes tx_type ---

#[test]
fn signing_message_includes_tx_type() {
    let (sk, pk) = ed25519::generate_keypair();
    let (_, recipient_pk) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk);

    let input = TxIn {
        prev_output: OutPoint { txid: Hash256::from_bytes([0x01; 32]), vout: 0 },
    };

    // Notarization tx
    let mut tx0 = Transaction {
        version: 1,
        tx_type: 0,
        inputs: vec![input.clone()],
        outputs: vec![],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };
    let msg0 = tx0.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx0.issuer_sig = priv_key.sign(&msg0).unwrap();

    // Transfer tx (same timestamp but different type)
    let mut tx1 = Transaction {
        version: 1,
        tx_type: 1,
        inputs: vec![input],
        outputs: vec![TxOut {
            value: 50_000,
            address: noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(recipient_pk.clone())),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };
    let msg1 = tx1.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx1.issuer_sig = priv_key.sign(&msg1).unwrap();

    assert_ne!(msg0, msg1, "signing message must differ between tx types");
}

// --- Property: signing message includes recipient ---

#[test]
fn signing_message_includes_recipient() {
    let (_sk, pk) = ed25519::generate_keypair();
    let (_, r1_pk) = ed25519::generate_keypair();
    let (_, r2_pk) = ed25519::generate_keypair();

    let input = TxIn {
        prev_output: OutPoint { txid: Hash256::from_bytes([0x01; 32]), vout: 0 },
    };

    let tx1 = Transaction {
        version: 1,
        tx_type: 1,
        inputs: vec![input.clone()],
        outputs: vec![TxOut {
            value: 50_000,
            address: noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(r1_pk)),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    let tx2 = Transaction {
        version: 1,
        tx_type: 1,
        inputs: vec![input],
        outputs: vec![TxOut {
            value: 50_000,
            address: noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(r2_pk)),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    let msg1 = tx1.compute_signing_message_for_chain(test_chain_id()).unwrap();
    let msg2 = tx2.compute_signing_message_for_chain(test_chain_id()).unwrap();
    assert_ne!(
        msg1, msg2,
        "signing message must change when recipient changes"
    );
}

// --- Property: signing message includes amount ---

#[test]
fn signing_message_includes_amount() {
    let (_sk, pk) = ed25519::generate_keypair();
    let (_, r_pk) = ed25519::generate_keypair();
    let recipient = noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(r_pk));

    let input = TxIn {
        prev_output: OutPoint { txid: Hash256::from_bytes([0x01; 32]), vout: 0 },
    };

    let tx1 = Transaction {
        version: 1,
        tx_type: 1,
        inputs: vec![input.clone()],
        outputs: vec![TxOut {
            value: 50_000,
            address: recipient.clone(),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    let tx2 = Transaction {
        version: 1,
        tx_type: 1,
        inputs: vec![input],
        outputs: vec![TxOut {
            value: 100_000,
            address: recipient,
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
    };

    let msg1 = tx1.compute_signing_message_for_chain(test_chain_id()).unwrap();
    let msg2 = tx2.compute_signing_message_for_chain(test_chain_id()).unwrap();
    assert_ne!(
        msg1, msg2,
        "signing message must change when amount changes"
    );
}
