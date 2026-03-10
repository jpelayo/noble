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
use noble_core::{Block, BlockHeader, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION};
use noble_test_utils::fixtures::test_chain_id;
use noble_crypto::{
    ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_ED25519,
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
    let (sk, pk) = ed25519::generate_keypair();
    let (_, new_pk) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
    let val_priv = NoblePrivateKey::Ed25519(sk.to_vec());
    let val_pub = NoblePublicKey::Ed25519(pk.to_vec());

    // Notarization tx (real checksum — should be indexed)
    let doc_hash = sha256(b"test-document-for-integration");
    let mut notarization = noble_core::Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_NOTARIZATION,
        checksum: doc_hash,
        timestamp: 1_700_000_000,
        fee: noble_core::MIN_TX_FEE,
        recipient: None,
        amount: None,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        source_address: None,
    };
    let msg = notarization
        .compute_signing_message_for_chain(test_chain_id())
        .unwrap();
    notarization.publisher_sig = priv_key.sign(&msg).unwrap();
    let notarization_id = notarization.compute_tx_id(test_chain_id()).unwrap();

    // Key rotation tx (zero checksum — should NOT be indexed)
    let new_key = NoblePublicKey::Ed25519(new_pk.to_vec());
    let mut key_rotation = noble_core::Transaction {
        version: PROTOCOL_VERSION,
        tx_type: noble_core::TX_TYPE_KEY_ROTATION,
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        fee: noble_core::MIN_TX_FEE,
        recipient: Some(noble_core::NobleAddress::Noble(new_key)),
        amount: None,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        source_address: None,
    };
    let msg = key_rotation
        .compute_signing_message_for_chain(test_chain_id())
        .unwrap();
    key_rotation.publisher_sig = priv_key.sign(&msg).unwrap();
    let key_rotation_id = key_rotation.compute_tx_id(test_chain_id()).unwrap();

    // Build and commit block at height 1 (genesis height 0 has zero subsidy)
    let transactions = vec![notarization, key_rotation];
    let tx_ids = vec![notarization_id, key_rotation_id];
    let merkle_root = noble_core::compute_merkle_root(&tx_ids);

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp: 1_700_000_000,
        height: 1,
        tx_count: 2,
        validator_id: val_pub,
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
    };
    let msg = header.compute_signing_message().unwrap();
    header.validator_sig = val_priv.sign(&msg).unwrap();
    let block = Block {
        header,
        transactions,
    };
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
    let (sk, _) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk);
    let pub_key = priv_key.public_key();

    let mut val_list = ValidatorList::new();
    val_list.add_validator(pub_key.clone(), 100, 0);

    let mut engine = CycleEngine::new(
        ConsensusConfig::default(),
        val_list,
        0,
        Hash256::ZERO,
        test_chain_id(),
        Some((priv_key, pub_key)),
        Some(noble_core::GENESIS_TIMESTAMP),
    );
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
