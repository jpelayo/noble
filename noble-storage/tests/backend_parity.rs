// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Differential tests: RocksDB and MemoryStorage must behave identically.
//!
//! The two backends drifted apart once already, with consensus-splitting
//! consequences: RocksDB had no rejection branch for `outputs > inputs`, so it
//! minted coins on a block MemoryStorage rejected, and neither backend checked
//! that a spender owned the coins it was spending. Divergence is worse than
//! either bug alone — nodes on different backends would disagree about which
//! blocks are valid.
//!
//! Each scenario here feeds the *same* block to both backends and asserts they
//! agree on accept/reject and on the resulting state. A test that passes on one
//! backend and fails on the other is the exact failure this file exists to
//! catch.

use noble_core::address::NobleAddress;
use noble_core::constants::{TX_TYPE_COINBASE, TX_TYPE_TRANSFER};
use noble_core::{Block, OutPoint, Transaction, TxIn, TxOut};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope, SCHEME_SECP256K1};
use noble_storage::error::StorageError;
use noble_storage::memory::MemoryStorage;
use noble_storage::rocks::RocksDbStorage;
use noble_storage::traits::StorageEngine;

/// Outcome reduced to a comparable shape: backends must agree on this.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Committed,
    RejectedOwnership,
    RejectedConservation,
    RejectedMissingInput,
    RejectedOther(String),
}

fn classify(result: Result<(), StorageError>) -> Outcome {
    use noble_core::error::ValidationError as VE;
    match result {
        Ok(()) => Outcome::Committed,
        Err(StorageError::InvalidTransaction { reason: VE::InputOwnershipMismatch { .. }, .. }) => {
            Outcome::RejectedOwnership
        }
        Err(StorageError::InvalidTransaction { reason: VE::OutputsExceedInputs { .. }, .. }) => {
            Outcome::RejectedConservation
        }
        Err(StorageError::UtxoNotFound { .. }) => Outcome::RejectedMissingInput,
        Err(e) => Outcome::RejectedOther(format!("{e}")),
    }
}

fn keypair() -> (Vec<u8>, NoblePublicKey) {
    let (_sk, pk) = noble_crypto::secp256k1::generate_keypair();
    (pk.clone(), NoblePublicKey::Secp256k1(pk))
}

fn sig(pk: &[u8]) -> SignatureEnvelope {
    SignatureEnvelope {
        scheme_id: SCHEME_SECP256K1,
        public_key: pk.to_vec(),
        signature: vec![0u8; 64],
    }
}

fn base_tx(tx_type: u8, issuer: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        tx_type,
        inputs: Vec::new(),
        outputs: Vec::new(),
        checksum: Hash256::ZERO,
        timestamp: 1_700_000_000,
        issuer_sig: sig(issuer),
        additional_sigs: Vec::new(),
        declared_cosigners: Vec::new(),
        metadata: Vec::new(),
        encrypted_locator: None,
        expires_at: None,
        external_attestations: Vec::new(),
        gateway_address: None,
        contract_data: None,
    }
}

fn coinbase(issuer: &[u8], value: u64, to: &NobleAddress) -> Transaction {
    let mut tx = base_tx(TX_TYPE_COINBASE, issuer);
    tx.inputs = vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }];
    tx.outputs = vec![TxOut { value, address: to.clone() }];
    tx
}

fn transfer(issuer: &[u8], inputs: Vec<OutPoint>, outputs: Vec<(u64, NobleAddress)>) -> Transaction {
    let mut tx = base_tx(TX_TYPE_TRANSFER, issuer);
    tx.inputs = inputs.into_iter().map(|prev_output| TxIn { prev_output }).collect();
    tx.outputs = outputs.into_iter().map(|(value, address)| TxOut { value, address }).collect();
    tx
}

fn block_with(height: u64, txs: Vec<Transaction>) -> Block {
    let mut b = noble_test_utils::fixtures::test_genesis_block();
    b.header.height = height;
    b.header.tx_count = txs.len() as u32;
    b.transactions = txs;
    b
}

fn chain_id() -> u32 {
    noble_test_utils::fixtures::test_chain_id()
}

fn ids_of(block: &Block) -> Vec<Hash256> {
    block
        .transactions
        .iter()
        .map(|tx| tx.compute_tx_id(chain_id()).unwrap())
        .collect()
}

fn commit(engine: &dyn StorageEngine, block: &Block) -> Result<(), StorageError> {
    let hash = block.header.compute_block_hash().unwrap();
    engine.commit_block(block, &hash, &ids_of(block))
}

/// Run `scenario` against both backends and assert they agree.
///
/// Returns the shared outcome so a caller can assert what it should be —
/// agreeing on the *wrong* answer must still be catchable.
fn assert_backends_agree(
    label: &str,
    scenario: impl Fn(&dyn StorageEngine) -> Result<(), StorageError>,
) -> Outcome {
    let mem = MemoryStorage::new();
    let mem_outcome = classify(scenario(&mem));

    let dir = tempfile::tempdir().unwrap();
    let rocks = RocksDbStorage::open(dir.path()).unwrap();
    let rocks_outcome = classify(scenario(&rocks));

    assert_eq!(
        mem_outcome, rocks_outcome,
        "{label}: backends disagree — MemoryStorage={mem_outcome:?} RocksDB={rocks_outcome:?}"
    );
    mem_outcome
}

/// Height of the funding block. Genesis (0) pays no subsidy by design, so
/// funding happens at height 1 and must pay *exactly* `subsidy_at_height(1)` —
/// the commit-time reward rule checks it.
const FUND_HEIGHT: u64 = 1;

/// Value the funding coinbase creates (and therefore the spendable balance).
fn fund_value() -> u64 {
    noble_core::constants::subsidy_at_height(FUND_HEIGHT)
}

/// Give `owner` one spendable coinbase output, returning its outpoint.
fn funded(
    engine: &dyn StorageEngine,
    issuer: &[u8],
    owner: &NobleAddress,
) -> Result<OutPoint, StorageError> {
    let cb = coinbase(issuer, fund_value(), owner);
    let block = block_with(FUND_HEIGHT, vec![cb]);
    let ids = ids_of(&block);
    commit(engine, &block)?;
    Ok(OutPoint { txid: ids[0], vout: 0 })
}

#[test]
fn both_backends_accept_a_conserving_transfer() {
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);

    let outcome = assert_backends_agree("conserving transfer", |engine| {
        let funding = funded(engine, &pk_bytes, &owner)?;
        // COINBASE_MATURITY is 3, so spend well clear of it.
        let spend = block_with(10, vec![transfer(&pk_bytes, vec![funding], vec![(fund_value() - 1_000, owner.clone())])]);
        commit(engine, &spend)
    });

    assert_eq!(outcome, Outcome::Committed);
}

#[test]
fn both_backends_reject_spending_another_key_utxo() {
    // C1. Before this rule existed, BOTH backends committed this block —
    // anyone could spend anyone's coins.
    let (owner_bytes, owner_pk) = keypair();
    let (thief_bytes, thief_pk) = keypair();
    let owner = NobleAddress::Noble(owner_pk);
    let thief = NobleAddress::Noble(thief_pk);

    let outcome = assert_backends_agree("theft", |engine| {
        let victim_utxo = funded(engine, &owner_bytes, &owner)?;
        // Signed by the thief, spending the owner's coins to the thief.
        let steal = block_with(10, vec![transfer(&thief_bytes, vec![victim_utxo], vec![(fund_value() - 1_000, thief.clone())])]);
        commit(engine, &steal)
    });

    assert_eq!(outcome, Outcome::RejectedOwnership, "theft must be rejected by both backends");
}

#[test]
fn both_backends_reject_outputs_exceeding_inputs() {
    // C2. RocksDB used to commit this (minting coins) while MemoryStorage
    // rejected it — a backend-dependent consensus split.
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);

    let outcome = assert_backends_agree("minting", |engine| {
        let funding = funded(engine, &pk_bytes, &owner)?;
        let mint = block_with(10, vec![transfer(&pk_bytes, vec![funding], vec![(fund_value() + 1, owner.clone())])]);
        commit(engine, &mint)
    });

    assert_eq!(outcome, Outcome::RejectedConservation);
}

#[test]
fn both_backends_reject_a_missing_input() {
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);
    let ghost = OutPoint { txid: Hash256::from_bytes([0xEE; 32]), vout: 3 };

    let outcome = assert_backends_agree("missing input", |engine| {
        let spend = block_with(10, vec![transfer(&pk_bytes, vec![ghost.clone()], vec![(10, owner.clone())])]);
        commit(engine, &spend)
    });

    assert_eq!(outcome, Outcome::RejectedMissingInput);
}

#[test]
fn both_backends_reject_an_immature_input() {
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);

    let outcome = assert_backends_agree("immature input", |engine| {
        let funding = funded(engine, &pk_bytes, &owner)?;
        // Height 1 is only one confirmation after the height-0 coinbase.
        let spend = block_with(1, vec![transfer(&pk_bytes, vec![funding], vec![(fund_value() - 1_000, owner.clone())])]);
        commit(engine, &spend)
    });

    assert!(
        matches!(outcome, Outcome::RejectedOther(_)),
        "immature spend must be rejected by both backends, got {outcome:?}"
    );
}

/// A fee-distribution transaction (`TX_TYPE_FEE`) paying `value`.
///
/// Carries the null coinbase input, matching how the proposer builds it
/// (`noble-consensus/src/proposal.rs`): `Transaction::is_coinbase()` requires
/// exactly one input with `OutPoint::COINBASE_PREVOUT`, and without it both
/// backends would treat this as an ordinary spend with no inputs.
fn fee_distribution(issuer: &[u8], value: u64, to: &NobleAddress) -> Transaction {
    let mut tx = base_tx(noble_core::constants::TX_TYPE_FEE, issuer);
    tx.inputs = vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }];
    tx.outputs = vec![TxOut { value, address: to.clone() }];
    tx
}

#[test]
fn both_backends_accept_the_split_reward_format() {
    // M6: RocksDB accepted two reward layouts (split reward + TX_TYPE_FEE, and
    // the legacy merged coinbase) while MemoryStorage knew only the legacy one.
    // A split-format block therefore committed on one backend and was rejected
    // by the other — a consensus split decided by which storage engine a node
    // happened to run.
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);

    let outcome = assert_backends_agree("split reward format", |engine| {
        // Fund, then spend so the block carries a real fee to distribute.
        let funding = funded(engine, &pk_bytes, &owner)?;
        let fee = 1_000u64;
        let spend = transfer(&pk_bytes, vec![funding], vec![(fund_value() - fee, owner.clone())]);

        // Split layout: index 0 pays exactly the subsidy, index 1 pays the fees.
        let height = 10;
        let block = block_with(
            height,
            vec![
                coinbase(&pk_bytes, noble_core::constants::subsidy_at_height(height), &owner),
                fee_distribution(&pk_bytes, fee, &owner),
                spend,
            ],
        );
        commit(engine, &block)
    });

    assert_eq!(outcome, Outcome::Committed, "split reward format must commit on BOTH backends");
}

#[test]
fn both_backends_reject_a_split_reward_that_overpays() {
    // The dual-format acceptance must not become a way to mint: a fee-
    // distribution output larger than the fees actually collected is invalid
    // on both backends.
    let (pk_bytes, pk) = keypair();
    let owner = NobleAddress::Noble(pk);

    let outcome = assert_backends_agree("overpaying fee distribution", |engine| {
        let funding = funded(engine, &pk_bytes, &owner)?;
        let fee = 1_000u64;
        let spend = transfer(&pk_bytes, vec![funding], vec![(fund_value() - fee, owner.clone())]);
        let height = 10;
        let block = block_with(
            height,
            vec![
                coinbase(&pk_bytes, noble_core::constants::subsidy_at_height(height), &owner),
                fee_distribution(&pk_bytes, fee + 5_000, &owner), // claims more than collected
                spend,
            ],
        );
        commit(engine, &block)
    });

    assert!(
        matches!(outcome, Outcome::RejectedOther(ref m) if m.contains("fee distribution mismatch")),
        "overpaying fee distribution must be rejected by both backends, got {outcome:?}"
    );
}

#[test]
fn a_rejected_block_leaves_no_state_behind_on_either_backend() {
    // L20: MemoryStorage used to mutate its maps before the economic checks,
    // so a rejection left a partially-applied block. Both backends must now
    // look untouched after a failed commit.
    let (owner_bytes, owner_pk) = keypair();
    let (thief_bytes, thief_pk) = keypair();
    let owner = NobleAddress::Noble(owner_pk);
    let thief = NobleAddress::Noble(thief_pk);

    let check = |engine: &dyn StorageEngine| -> Result<(), StorageError> {
        let victim_utxo = funded(engine, &owner_bytes, &owner)?;
        let tip_before = engine.get_chain_tip()?;

        let steal = block_with(10, vec![transfer(&thief_bytes, vec![victim_utxo.clone()], vec![(fund_value() - 1_000, thief.clone())])]);
        let hash = steal.header.compute_block_hash().unwrap();
        let err = engine.commit_block(&steal, &hash, &ids_of(&steal)).unwrap_err();

        // The victim's UTXO must still be spendable and the tip unmoved.
        assert!(
            engine.get_utxo(&victim_utxo)?.is_some(),
            "rejected commit consumed the victim's UTXO"
        );
        assert_eq!(engine.get_chain_tip()?, tip_before, "rejected commit advanced the tip");
        assert!(
            engine.get_block(&hash).is_err() || engine.get_block(&hash).unwrap().header.height != 10,
            "rejected block was stored anyway"
        );
        Err(err)
    };

    let outcome = assert_backends_agree("atomicity", check);
    assert_eq!(outcome, Outcome::RejectedOwnership);
}
