// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Backend-neutral economic validation for block commit.
//!
//! Every rule here needs resolved UTXOs, so it cannot live in stateless
//! validation — but it also must not live in a single backend, because that is
//! exactly how the two backends drifted apart: RocksDB accepted `outputs >
//! inputs` (minting coins) while MemoryStorage rejected it, and *neither*
//! checked that the spender owned the coins being spent.
//!
//! [`validate_block_economics`] is therefore called by both backends, before
//! either of them mutates anything. Two properties follow:
//!
//! 1. **Parity** — the backends accept and reject exactly the same blocks,
//!    because the decision is made by one shared function over a read-only view.
//! 2. **Atomicity** — a block that fails economics never reaches the mutation
//!    stage, so a rejected commit cannot leave partial state behind.

use std::collections::{HashMap, HashSet};

use noble_core::stateful_validation::{
    is_minting_tx_type, validate_resolved_inputs, ResolvedInput,
};
use noble_core::{Block, OutPoint, UtxoEntry};
use noble_crypto::Hash256;

use crate::error::StorageError;

/// Read-only UTXO access needed to validate a block.
///
/// Deliberately minimal: preparation must not be able to mutate, and a narrow
/// view keeps both backends honest about what the shared rules may depend on.
pub trait UtxoReadView {
    /// Look up a UTXO in the persistent set. `Ok(None)` means "not present",
    /// which is a rejection — never treat a missing input as zero value.
    fn utxo_at(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, StorageError>;
}

/// Aggregate economic result of validating a whole block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockEconomics {
    /// Sum of every regular transaction's fee, in atomic units.
    pub total_fees: u64,
    /// Outpoints consumed by this block, in encounter order.
    pub spent: Vec<OutPoint>,
}

/// Validate ownership, maturity and value conservation for every regular
/// transaction in `block`.
///
/// `tx_ids` must be positionally aligned with `block.transactions` (the same
/// ids the caller will index by), because outputs created earlier in this block
/// are addressed by them.
///
/// Minting transactions (coinbase, fee distribution) are skipped here — they
/// create value by protocol rule and are checked by the commit-time reward
/// rules instead.
///
/// Resolution order per input mirrors what the backends already do: an output
/// created earlier in *this* block wins over the persistent set, and such
/// outputs are maturity-exempt so intra-block chaining (CPFP) keeps working.
pub fn validate_block_economics<V: UtxoReadView>(
    view: &V,
    block: &Block,
    tx_ids: &[Hash256],
) -> Result<BlockEconomics, StorageError> {
    if tx_ids.len() != block.transactions.len() {
        return Err(StorageError::Database(format!(
            "tx_ids length {} does not match block tx count {}",
            tx_ids.len(),
            block.transactions.len()
        )));
    }

    let height = block.header.height;
    // Outputs created by earlier transactions in this same block.
    let mut created: HashMap<OutPoint, UtxoEntry> = HashMap::new();
    // Every outpoint consumed so far, to catch a double spend *within* the block.
    let mut spent_set: HashSet<OutPoint> = HashSet::new();
    let mut economics = BlockEconomics::default();

    for (tx_index, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
        if !is_minting_tx_type(tx.tx_type) && !tx.is_coinbase() {
            // Resolve every input first; keep the owned entries alive for the
            // borrows handed to the validator.
            let mut owned: Vec<(OutPoint, UtxoEntry, bool)> = Vec::with_capacity(tx.inputs.len());
            for txin in &tx.inputs {
                let outpoint = txin.prev_output.clone();

                if spent_set.contains(&outpoint) {
                    return Err(StorageError::Database(format!(
                        "double spend within block: {}:{} consumed twice",
                        outpoint.txid, outpoint.vout
                    )));
                }

                let (entry, same_block) = match created.get(&outpoint) {
                    Some(e) => (e.clone(), true),
                    None => match view.utxo_at(&outpoint)? {
                        Some(e) => (e, false),
                        // Typed, not stringly: callers classify a missing input
                        // without parsing text, and this preserves the error
                        // both backends already returned for this case.
                        None => {
                            return Err(StorageError::UtxoNotFound {
                                txid: outpoint.txid.to_string(),
                                vout: outpoint.vout,
                            })
                        }
                    },
                };
                owned.push((outpoint, entry, same_block));
            }

            let resolved: Vec<ResolvedInput<'_>> = owned
                .iter()
                .map(|(outpoint, utxo, same_block)| ResolvedInput {
                    outpoint,
                    utxo,
                    same_block: *same_block,
                })
                .collect();

            // C1 + C2, identically for every backend and every acceptance path.
            let accounting = validate_resolved_inputs(tx, &resolved, height).map_err(|reason| {
                StorageError::InvalidTransaction { tx_index, reason }
            })?;

            economics.total_fees = economics.total_fees.checked_add(accounting.fee).ok_or_else(
                || StorageError::Database("block fee accumulation overflow".into()),
            )?;

            for (outpoint, _, _) in owned {
                spent_set.insert(outpoint.clone());
                economics.spent.push(outpoint);
            }
        }

        // Outputs of this transaction become spendable by later transactions in
        // the same block (registered even for minting txs, whose outputs are
        // ordinary UTXOs once created).
        for (vout, out) in tx.outputs.iter().enumerate() {
            created.insert(
                OutPoint { txid: *tx_id, vout: vout as u32 },
                UtxoEntry {
                    value: out.value,
                    address: out.address.clone(),
                    height,
                    is_coinbase: tx.is_coinbase(),
                },
            );
        }
    }

    Ok(economics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::address::NobleAddress;
    use noble_core::error::ValidationError;
    use noble_crypto::{NoblePublicKey, SignatureEnvelope, SCHEME_SECP256K1};

    struct MapView(HashMap<OutPoint, UtxoEntry>);

    impl UtxoReadView for MapView {
        fn utxo_at(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, StorageError> {
            Ok(self.0.get(outpoint).cloned())
        }
    }

    fn keypair() -> (Vec<u8>, NoblePublicKey) {
        let (_sk, pk) = noble_crypto::secp256k1::generate_keypair();
        (pk.clone(), NoblePublicKey::Secp256k1(pk))
    }

    fn transfer(issuer: &[u8], inputs: Vec<OutPoint>, outputs: Vec<u64>, owner: &NobleAddress) -> noble_core::Transaction {
        noble_core::Transaction {
            version: 1,
            tx_type: noble_core::constants::TX_TYPE_TRANSFER,
            inputs: inputs.into_iter().map(|prev_output| noble_core::TxIn { prev_output }).collect(),
            outputs: outputs
                .into_iter()
                .map(|value| noble_core::TxOut { value, address: owner.clone() })
                .collect(),
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: issuer.to_vec(),
                signature: vec![0u8; 64],
            },
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

    fn block_at(height: u64, txs: Vec<noble_core::Transaction>) -> Block {
        let mut b = noble_test_utils::fixtures::test_genesis_block();
        b.header.height = height;
        b.header.tx_count = txs.len() as u32;
        b.transactions = txs;
        b
    }

    const H: u64 = 100;

    #[test]
    fn foreign_owner_input_is_rejected_before_any_mutation() {
        let (issuer_bytes, _issuer) = keypair();
        let (_v_bytes, victim) = keypair();
        let op = OutPoint { txid: Hash256::from_bytes([9; 32]), vout: 0 };
        let view = MapView(HashMap::from([(
            op.clone(),
            UtxoEntry { value: 1_000, address: NobleAddress::Noble(victim), height: 0, is_coinbase: false },
        )]));
        let owner = NobleAddress::Noble(NoblePublicKey::Secp256k1(issuer_bytes.clone()));
        let block = block_at(H, vec![transfer(&issuer_bytes, vec![op], vec![900], &owner)]);
        let tx_ids = vec![Hash256::from_bytes([1; 32])];

        let err = validate_block_economics(&view, &block, &tx_ids).unwrap_err();
        assert!(
            matches!(err, StorageError::InvalidTransaction { tx_index: 0, reason: ValidationError::InputOwnershipMismatch { .. } }),
            "expected ownership rejection, got {err:?}"
        );
    }

    #[test]
    fn outputs_exceeding_inputs_are_rejected() {
        // The RocksDB minting hole, now closed for both backends.
        let (pk_bytes, pk) = keypair();
        let owner = NobleAddress::Noble(pk);
        let op = OutPoint { txid: Hash256::from_bytes([8; 32]), vout: 0 };
        let view = MapView(HashMap::from([(
            op.clone(),
            UtxoEntry { value: 1_000, address: owner.clone(), height: 0, is_coinbase: false },
        )]));
        let block = block_at(H, vec![transfer(&pk_bytes, vec![op], vec![1_001], &owner)]);
        let tx_ids = vec![Hash256::from_bytes([2; 32])];

        assert!(matches!(
            validate_block_economics(&view, &block, &tx_ids).unwrap_err(),
            StorageError::InvalidTransaction { reason: ValidationError::OutputsExceedInputs { .. }, .. }
        ));
    }

    #[test]
    fn valid_block_reports_summed_fees() {
        let (pk_bytes, pk) = keypair();
        let owner = NobleAddress::Noble(pk);
        let (a, b) = (
            OutPoint { txid: Hash256::from_bytes([7; 32]), vout: 0 },
            OutPoint { txid: Hash256::from_bytes([7; 32]), vout: 1 },
        );
        let view = MapView(HashMap::from([
            (a.clone(), UtxoEntry { value: 1_000, address: owner.clone(), height: 0, is_coinbase: false }),
            (b.clone(), UtxoEntry { value: 500, address: owner.clone(), height: 0, is_coinbase: false }),
        ]));
        let block = block_at(
            H,
            vec![
                transfer(&pk_bytes, vec![a], vec![900], &owner),
                transfer(&pk_bytes, vec![b], vec![400], &owner),
            ],
        );
        let tx_ids = vec![Hash256::from_bytes([3; 32]), Hash256::from_bytes([4; 32])];

        let econ = validate_block_economics(&view, &block, &tx_ids).expect("valid block");
        assert_eq!(econ.total_fees, 200);
        assert_eq!(econ.spent.len(), 2);
    }

    #[test]
    fn child_may_spend_parent_output_in_same_block() {
        // Intra-block chaining must keep working: the child's input is not in
        // the persistent view at all, only in the in-block overlay.
        let (pk_bytes, pk) = keypair();
        let owner = NobleAddress::Noble(pk);
        let funding = OutPoint { txid: Hash256::from_bytes([6; 32]), vout: 0 };
        let view = MapView(HashMap::from([(
            funding.clone(),
            UtxoEntry { value: 1_000, address: owner.clone(), height: 0, is_coinbase: false },
        )]));
        let parent_id = Hash256::from_bytes([5; 32]);
        let block = block_at(
            H,
            vec![
                transfer(&pk_bytes, vec![funding], vec![900], &owner),
                transfer(&pk_bytes, vec![OutPoint { txid: parent_id, vout: 0 }], vec![800], &owner),
            ],
        );
        let tx_ids = vec![parent_id, Hash256::from_bytes([15; 32])];

        let econ = validate_block_economics(&view, &block, &tx_ids).expect("CPFP block must commit");
        assert_eq!(econ.total_fees, 200); // 100 parent + 100 child
    }

    #[test]
    fn double_spend_within_one_block_is_rejected() {
        let (pk_bytes, pk) = keypair();
        let owner = NobleAddress::Noble(pk);
        let op = OutPoint { txid: Hash256::from_bytes([4; 32]), vout: 0 };
        let view = MapView(HashMap::from([(
            op.clone(),
            UtxoEntry { value: 1_000, address: owner.clone(), height: 0, is_coinbase: false },
        )]));
        let block = block_at(
            H,
            vec![
                transfer(&pk_bytes, vec![op.clone()], vec![900], &owner),
                transfer(&pk_bytes, vec![op], vec![800], &owner),
            ],
        );
        let tx_ids = vec![Hash256::from_bytes([11; 32]), Hash256::from_bytes([12; 32])];

        let err = validate_block_economics(&view, &block, &tx_ids).unwrap_err();
        assert!(format!("{err}").contains("double spend"), "got {err:?}");
    }

    #[test]
    fn missing_input_is_rejected_not_treated_as_zero() {
        let (pk_bytes, pk) = keypair();
        let owner = NobleAddress::Noble(pk);
        let missing = OutPoint { txid: Hash256::from_bytes([3; 32]), vout: 7 };
        let view = MapView(HashMap::new());
        let block = block_at(H, vec![transfer(&pk_bytes, vec![missing], vec![10], &owner)]);
        let tx_ids = vec![Hash256::from_bytes([13; 32])];

        assert!(matches!(
            validate_block_economics(&view, &block, &tx_ids).unwrap_err(),
            StorageError::UtxoNotFound { vout: 7, .. }
        ));
    }
}
