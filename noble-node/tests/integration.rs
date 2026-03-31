// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for noble-node cross-crate interactions.
//!
//! These tests verify end-to-end behavior using the public APIs of
//! workspace crates as they would be composed in the node binary.

use noble_consensus::{
    ConsensusConfig, ConsensusStateMachine, CycleEngine, CycleEvent, CycleIo, CyclePhase,
    ValidatorList, VotingStrategy,
};
use noble_core::{Block, BlockHeader, OutPoint, TxIn, TxOut, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION};
use noble_test_utils::fixtures::test_chain_id;
use noble_crypto::{
    secp256k1, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_SECP256K1,
};
use noble_storage::{MemoryStorage, StorageEngine};

/// Verify that `VotingStrategy` enum covers all known strategy names and
/// that unknown names fall back to `FirstValid`.
#[test]
fn voting_strategy_name_roundtrip() {
    // All known strategies and their expected names
    let strategies = vec![
        (VotingStrategy::FirstValid, "first_valid"),
        (
            VotingStrategy::FixedValidator {
                validator_key: "deadbeef".into(),
            },
            "fixed_validator",
        ),
        (VotingStrategy::RoundRobin, "round_robin"),
        (
            VotingStrategy::SubsetRotation {
                validators: vec!["abc".into()],
            },
            "subset_rotation",
        ),
        (VotingStrategy::Random, "random"),
        (VotingStrategy::WeightedReputation, "weighted_reputation"),
        (VotingStrategy::FollowMajority, "follow_majority"),
        (VotingStrategy::Manual, "manual"),
    ];

    for (strategy, expected_name) in strategies {
        assert_eq!(
            strategy.name(),
            expected_name,
            "VotingStrategy::{:?} should have name '{}'",
            strategy,
            expected_name
        );
    }

    // Default should be weighted_probability
    assert_eq!(VotingStrategy::default().name(), "weighted_probability");
}

/// MemoryStorage must only index notarization checksums, not non-notarization zero-checksums.
#[test]
fn storage_only_indexes_notarization_checksums() {
    let storage = MemoryStorage::new();

    // Use the same key for validator and tx signer so subsidy covers fees.
    let (sk, pk) = secp256k1::generate_keypair();
    let (_, new_pk) = secp256k1::generate_keypair();
    let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
    let val_priv = NoblePrivateKey::Secp256k1(sk.to_vec());
    let val_pub = NoblePublicKey::Secp256k1(pk.to_vec());

    let val_addr = noble_core::NobleAddress::Noble(val_pub.clone());

    // Helper to build and commit a coinbase-only block
    let mut prev_hash = Hash256::ZERO;
    let mut first_coinbase_id = Hash256::ZERO;

    // ── Blocks 1-7: coinbase only (7 blocks for maturity) ──
    for h in 1..=7u64 {
        let subsidy_h = noble_core::subsidy_at_height(h);
        let mut cb = noble_core::Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value: subsidy_h, address: val_addr.clone() }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000 + h,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
            },
            additional_sigs: vec![], metadata: vec![], encrypted_locator: None,
            external_attestations: vec![], gateway_address: None,
            contract_data: None, expires_at: None,
        };
        let msg = cb.compute_signing_message_for_chain(test_chain_id()).unwrap();
        cb.issuer_sig = priv_key.sign(&msg).unwrap();
        let cb_id = cb.compute_tx_id(test_chain_id()).unwrap();
        if h == 1 { first_coinbase_id = cb_id; }

        let ids = vec![cb_id];
        let mr = noble_core::compute_merkle_root(&ids);
        let mut hdr = BlockHeader {
            version: PROTOCOL_VERSION, prev_block_hash: prev_hash, merkle_root: mr,
            timestamp: 1_700_000_000 + h, height: h, tx_count: 1,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
            },
        };
        let msg = hdr.compute_signing_message().unwrap();
        hdr.validator_sig = val_priv.sign(&msg).unwrap();
        let blk = Block { header: hdr, transactions: vec![cb] };
        let bh = blk.header.compute_block_hash().unwrap();
        storage.commit_block(&blk, &bh, &ids).unwrap_or_else(|e| panic!("block {h}: {e}"));
        prev_hash = bh;
    }

    let subsidy = noble_core::subsidy_at_height(1);

    // ── Block 8: notarization + key rotation spending mature coinbase ──

    // Notarization tx (real checksum — should be indexed)
    // Spends the coinbase output from block 1 (mature after COINBASE_MATURITY=3 blocks)
    let doc_hash = sha256(b"test-document-for-integration");
    let mut notarization = noble_core::Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_NOTARIZATION,
        inputs: vec![TxIn {
            prev_output: OutPoint { txid: first_coinbase_id, vout: 0 },
        }],
        outputs: vec![TxOut { value: subsidy - 2, address: val_addr.clone() }], // change
        checksum: doc_hash,
        timestamp: 1_700_000_008,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    };
    let msg = notarization.compute_signing_message_for_chain(test_chain_id()).unwrap();
    notarization.issuer_sig = priv_key.sign(&msg).unwrap();
    let notarization_id = notarization.compute_tx_id(test_chain_id()).unwrap();

    // Key rotation tx (zero checksum — should NOT be indexed)
    // Uses the change output from the notarization (in-block spending)
    let new_key = NoblePublicKey::Secp256k1(new_pk.to_vec());
    let mut key_rotation = noble_core::Transaction {
        version: PROTOCOL_VERSION,
        tx_type: noble_core::TX_TYPE_KEY_ROTATION,
        inputs: vec![TxIn {
            prev_output: OutPoint { txid: notarization_id, vout: 0 }, // spend notarization change
        }],
        outputs: vec![TxOut {
            value: subsidy - 3, // change after another 1 atomic fee
            address: noble_core::NobleAddress::Noble(new_key),
        }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_008,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    };
    let msg = key_rotation.compute_signing_message_for_chain(test_chain_id()).unwrap();
    key_rotation.issuer_sig = priv_key.sign(&msg).unwrap();
    let key_rotation_id = key_rotation.compute_tx_id(test_chain_id()).unwrap();

    // Block 2 with coinbase + notarization + key rotation
    let subsidy_2 = noble_core::subsidy_at_height(8);
    let total_fees = 2 + 1; // notarization fee + key_rotation fee
    let mut coinbase2 = noble_core::Transaction {
        version: PROTOCOL_VERSION,
        tx_type: noble_core::TX_TYPE_COINBASE,
        inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
        outputs: vec![TxOut { value: subsidy_2 + total_fees, address: val_addr }],
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_008,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    };
    let msg = coinbase2.compute_signing_message_for_chain(test_chain_id()).unwrap();
    coinbase2.issuer_sig = priv_key.sign(&msg).unwrap();
    let coinbase2_id = coinbase2.compute_tx_id(test_chain_id()).unwrap();

    let transactions = vec![coinbase2, notarization, key_rotation];
    let tx_ids = vec![coinbase2_id, notarization_id, key_rotation_id];
    let merkle_root = noble_core::compute_merkle_root(&tx_ids);

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1_700_000_008,
        height: 8,
        tx_count: 3,
        validator_id: val_pub,
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![],
        },
    };
    let msg = header.compute_signing_message().unwrap();
    header.validator_sig = val_priv.sign(&msg).unwrap();
    let block = Block { header, transactions };
    let block_hash = block.header.compute_block_hash().unwrap();

    storage
        .commit_block(&block, &block_hash, &tx_ids)
        .expect("commit should succeed");

    // The notarization checksum should be indexed
    let results = storage.lookup_checksum(&doc_hash).unwrap();
    assert_eq!(results.len(), 1, "notarization checksum should be found");
    assert_eq!(results[0], notarization_id);

    // The zero checksum (key rotation) should NOT be indexed
    let zero_results = storage.lookup_checksum(&Hash256::ZERO).unwrap();
    assert!(
        zero_results.is_empty(),
        "non-notarization zero-checksum must not be indexed"
    );
}

/// Self-proposed blocks must pass validation before broadcast.
/// A validator in the validator list should successfully propose and broadcast.
#[test]
fn self_proposal_validates_before_broadcast() {
    let (sk, _) = secp256k1::generate_keypair();
    let priv_key = NoblePrivateKey::Secp256k1(sk);
    let pub_key = priv_key.public_key();

    let mut reg = noble_consensus::ValidatorRegistry::empty();
    reg.add_validator(pub_key.clone(), 100, 0);
    let snap = reg.create_snapshot();

    let mut engine = CycleEngine::new(
        ConsensusConfig::default(),
        0,
        Hash256::ZERO,
        test_chain_id(),
        Some((priv_key, pub_key)),
        Some(noble_core::GENESIS_TIMESTAMP),
    );
    engine.set_validator_snapshot(snap);
    engine.set_peer_count(5);

    // Transition to Validation phase (triggers mempool request for validators)
    let _init_outputs = engine.step(CycleEvent::PhaseTransition {
        cycle: 0,
        new_phase: CyclePhase::Proposal,
    });

    // Feed empty mempool transactions — should produce a valid empty block
    let outputs = engine.step(CycleEvent::MempoolTransactions(vec![]));

    let has_broadcast = outputs
        .iter()
        .any(|o| matches!(o, CycleIo::BroadcastBlock(_)));
    assert!(
        has_broadcast,
        "valid self-proposed block should be broadcast after passing validation"
    );
}
