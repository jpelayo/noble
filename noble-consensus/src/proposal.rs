// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Block proposal: select transactions from mempool and build a valid block.

use noble_core::{
    compute_merkle_root, Block, BlockHeader, NobleAddress, OutPoint, Transaction, TxIn, TxOut,
    PROTOCOL_VERSION, TX_TYPE_COINBASE, TX_TYPE_FEE, subsidy_at_height,
    wire::WireFormat,
};
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};
use tracing;

/// Look up a UTXO's value by outpoint. Used by propose_block to compute fees.
pub trait UtxoValueLookup {
    fn utxo_value(&self, outpoint: &OutPoint) -> Option<u64>;

    /// Value of `outpoint` **iff** it is spendable (mature) at `at_height`,
    /// else `None`. The proposer uses this so it never selects a tx spending an
    /// output that became immature (e.g. after a backward reorg) and would only
    /// fail at commit. Default ignores maturity — back-compat for test/Noop
    /// impls; the real storage-backed impl overrides it.
    fn utxo_spendable_value(&self, outpoint: &OutPoint, _at_height: u64) -> Option<u64> {
        self.utxo_value(outpoint)
    }
}

/// Propose a new block from a pre-sorted list of mempool transactions.
///
/// Automatically prepends a coinbase transaction at index 0 carrying
/// `subsidy_at_height(height) + total_fees` to the reward address
/// (or the validator address if no reward address is configured).
///
/// `mempool_txs` should already be sorted by fee descending (highest first).
/// `utxo_lookup` is used to resolve input UTXO values for fee computation.
/// `reward_address` overrides the coinbase recipient (subsidy + validator fee share).
///
/// Returns the complete signed block.
#[allow(clippy::too_many_arguments)]
pub fn propose_block(
    mempool_txs: &[Transaction],
    prev_hash: Hash256,
    height: u64,
    timestamp: u64,
    chain_id: u32,
    validator_key: &NoblePrivateKey,
    validator_pubkey: &NoblePublicKey,
    max_size: usize,
    utxo_lookup: &dyn UtxoValueLookup,
    reward_address: Option<&NobleAddress>,
) -> Result<Block, String> {
    let validator_addr = reward_address
        .cloned()
        .unwrap_or_else(|| NobleAddress::Noble(validator_pubkey.clone()));

    // Reserve headroom for the coinbase + fee-distribution txs, which are
    // prepended AFTER selection. Without this, user txs packed to `max_size`
    // would push the final block over MAX_BLOCK_SIZE and the proposer would
    // build a block that fails its own commit validation. 2×MAX_TX_SIZE bounds
    // a coinbase + a (gateway-heavy) fee-dist tx; a final exact check below is
    // the hard guarantee.
    let size_budget = max_size.saturating_sub(2 * noble_core::MAX_TX_SIZE);

    // Select transactions that fit within the budget.
    let mut selected: Vec<Transaction> = Vec::new();
    let mut total_size: usize = 0;
    let mut total_fees: u64 = 0;
    // Track gateway fee shares: gateway_wire_bytes → accumulated share
    let mut gateway_shares: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    // Outputs created by already-selected txs in THIS block (intra-block CPFP):
    // a child's input may reference a parent output that isn't on-chain yet.
    let mut in_block_value: std::collections::HashMap<OutPoint, u64> = std::collections::HashMap::new();

    for tx in mempool_txs {
        // Resolvability gate (runs BEFORE size accounting — an excluded tx
        // consumes no block space). Each input must be either a mature on-chain
        // UTXO or an output created earlier in this same block. A tx with an
        // unresolvable/immature/spent input is skipped; because the feed is
        // topo-sorted, its descendants are skipped too (their parent never
        // enters `in_block_value`).
        let mut input_total: u64 = 0;
        let mut resolved = true;
        for i in &tx.inputs {
            if let Some(v) = utxo_lookup.utxo_spendable_value(&i.prev_output, height) {
                input_total = input_total.saturating_add(v);
            } else if let Some(&v) = in_block_value.get(&i.prev_output) {
                input_total = input_total.saturating_add(v);
            } else {
                resolved = false;
                break;
            }
        }
        if !resolved {
            continue;
        }

        let tx_size = tx.wire_bytes().len();
        if total_size + tx_size > size_budget {
            break;
        }
        total_size += tx_size;

        // Fee: sum(input values) - sum(output values).
        let output_total = tx.total_output_value();
        let fee = input_total.saturating_sub(output_total);
        total_fees += fee;

        // Gateway fee split: if gateway_address is present, gateway gets 50% of fee
        if let Some(ref gw) = tx.gateway_address {
            let gw_share = fee / 2;
            if gw_share > 0 {
                *gateway_shares.entry(gw.clone()).or_default() += gw_share;
            }
        }

        // Register this tx's outputs so a later in-block child can resolve them.
        let tx_id = tx
            .compute_tx_id(chain_id)
            .map_err(|e| format!("failed to compute tx_id during selection: {e}"))?;
        for (vout, out) in tx.outputs.iter().enumerate() {
            in_block_value.insert(OutPoint { txid: tx_id, vout: vout as u32 }, out.value);
        }

        selected.push(tx.clone());
    }

    // Block Reward transaction (index 0): subsidy only → validator
    let subsidy = subsidy_at_height(height);

    let mut block_reward = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_COINBASE,
        inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
        outputs: vec![TxOut {
            value: subsidy,
            address: validator_addr.clone(),
        }],
        checksum: Hash256::ZERO,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: validator_pubkey.scheme_id(),
            public_key: validator_pubkey.key_bytes().to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        declared_cosigners: Vec::new(),
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    };
    let reward_msg = block_reward
        .compute_signing_message_for_chain(chain_id)
        .map_err(|e| format!("failed to compute block reward signing message: {e}"))?;
    block_reward.issuer_sig = validator_key
        .sign(&reward_msg)
        .map_err(|e| format!("failed to sign block reward: {e}"))?;

    // Fee Distribution transaction (index 1): collected fees → validator + gateways
    // Omitted entirely if total_fees == 0 (no fee-paying txs in block).
    let total_gateway_share: u64 = gateway_shares.values().sum();
    let validator_fee_share = total_fees.saturating_sub(total_gateway_share);

    let fee_dist_tx = if total_fees > 0 {
        let mut fee_outputs = vec![TxOut {
            value: validator_fee_share,
            address: validator_addr,
        }];

        // Add gateway outputs (sorted for deterministic ordering)
        let mut gw_entries: Vec<_> = gateway_shares.into_iter().collect();
        gw_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (gw_wire, gw_amount) in gw_entries {
            match NobleAddress::from_wire_bytes(&gw_wire) {
                Ok(gw_addr) => {
                    fee_outputs.push(TxOut {
                        value: gw_amount,
                        address: gw_addr,
                    });
                }
                Err(e) => {
                    // Recover the gateway's share back to the validator.
                    tracing::warn!(
                        "gateway address decode failed ({e}), recovering {gw_amount} groats to validator"
                    );
                    fee_outputs[0].value += gw_amount;
                }
            }
        }

        let mut fee_tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_FEE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: fee_outputs,
            checksum: Hash256::ZERO,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: validator_pubkey.scheme_id(),
                public_key: validator_pubkey.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            declared_cosigners: Vec::new(),
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        let fee_msg = fee_tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| format!("failed to compute fee distribution signing message: {e}"))?;
        fee_tx.issuer_sig = validator_key
            .sign(&fee_msg)
            .map_err(|e| format!("failed to sign fee distribution: {e}"))?;
        Some(fee_tx)
    } else {
        None
    };

    // Assemble: Block Reward + Fee Distribution (if any) + user transactions
    let mut all_txs = Vec::with_capacity(2 + selected.len());
    all_txs.push(block_reward);
    if let Some(fee_tx) = fee_dist_tx {
        all_txs.push(fee_tx);
    }
    all_txs.extend(selected);

    // Final-size hard guard (review #7): the coinbase + fee-dist overhead is
    // now part of the block. The `size_budget` reserve above makes this pass in
    // every realistic case; if a pathological gateway count still overflows,
    // fail closed (skip proposing this cycle) rather than emit an oversized
    // block that fails its own commit validation.
    let assembled_size: usize = all_txs.iter().map(|t| t.wire_bytes().len()).sum();
    if assembled_size > max_size {
        return Err(format!(
            "assembled block {assembled_size} bytes exceeds max {max_size} (coinbase/fee-dist overhead); skipping proposal"
        ));
    }

    // Compute tx_ids and merkle root (coinbase included)
    let tx_ids: Vec<Hash256> = all_txs
        .iter()
        .map(|tx| tx.compute_tx_id(chain_id))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to compute tx_id: {e}"))?;
    let merkle_root = compute_merkle_root(&tx_ids);



    // Build header
    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp,
        height,
        tx_count: all_txs.len() as u32,
        validator_id: validator_pubkey.clone(),
        validator_sig: SignatureEnvelope {
            scheme_id: validator_pubkey.scheme_id(),
            public_key: validator_pubkey.key_bytes().to_vec(),
            signature: vec![],
        },
    };

    // Sign the header
    let msg = header
        .compute_signing_message()
        .map_err(|e| format!("failed to compute signing message: {e}"))?;
    header.validator_sig = validator_key
        .sign(&msg)
        .map_err(|e| format!("failed to sign block: {e}"))?;

    Ok(Block {
        header,
        transactions: all_txs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MAX_BLOCK_SIZE, MIN_TX_FEE};
    use noble_test_utils::fixtures::test_chain_id;
    use noble_crypto::{secp256k1, sha256, NoblePrivateKey, NobleSigner, SCHEME_SECP256K1};

    /// Test UTXO lookup that returns a fixed value for any outpoint.
    struct FixedUtxoLookup(u64);
    impl UtxoValueLookup for FixedUtxoLookup {
        fn utxo_value(&self, _outpoint: &OutPoint) -> Option<u64> {
            Some(self.0)
        }
    }

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn make_test_tx(doc: &[u8], _fee: u64) -> Transaction {
        use noble_core::{NobleAddress, OutPoint, TxIn, TxOut};
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let checksum = sha256(doc);
        let addr = NobleAddress::Noble(noble_crypto::NoblePublicKey::Secp256k1(pk.clone()));
        let prev_outpoint = OutPoint {
            txid: sha256(&pk),
            vout: 0,
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn { prev_output: prev_outpoint }],
            outputs: vec![TxOut { value: 100_000_000, address: addr }],
            checksum,
            timestamp: now_secs(),
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk,
                signature: vec![],
            },
            additional_sigs: vec![],
            declared_cosigners: Vec::new(),
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
            expires_at: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn propose_empty_block() {
        let (val_priv, val_pub) = make_validator();
        let block = propose_block(
            &[],
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
            None,
        )
        .unwrap();

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.tx_count, 1); // coinbase only
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
        assert_eq!(block.header.validator_id, val_pub);
    }

    #[test]
    fn propose_block_with_transactions() {
        let (val_priv, val_pub) = make_validator();
        let tx1 = make_test_tx(b"doc1", MIN_TX_FEE * 10);
        let tx2 = make_test_tx(b"doc2", MIN_TX_FEE * 5);
        let txs = vec![tx1, tx2];

        let block = propose_block(
            &txs,
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
            None,
        )
        .unwrap();

        assert_eq!(block.header.tx_count, 3); // coinbase + 2 user txs
        assert_eq!(block.transactions.len(), 3);
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn propose_block_respects_size_limit() {
        let (val_priv, val_pub) = make_validator();
        let tx1 = make_test_tx(b"doc1", MIN_TX_FEE * 10);
        let tx2 = make_test_tx(b"doc2", MIN_TX_FEE * 5);
        let txs = vec![tx1.clone(), tx2];

        // Budget for exactly one tx ON TOP OF the coinbase/fee-dist reserve
        // (propose_block reserves 2×MAX_TX_SIZE for the prepended coinbase +
        // fee-dist; user-tx selection runs against max_size − reserve).
        let tx1_size = tx1.wire_bytes().len();
        let block = propose_block(
            &txs,
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            2 * noble_core::MAX_TX_SIZE + tx1_size, // reserve + exactly one tx
            &FixedUtxoLookup(2_000_000),
            None,
        )
        .unwrap();

        // coinbase + 1 user tx (second didn't fit)
        assert_eq!(
            block.header.tx_count, 2,
            "should include coinbase + one user tx due to size limit"
        );
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn proposed_block_passes_validation() {
        let (val_priv, val_pub) = make_validator();
        let tx = make_test_tx(b"validated_doc", MIN_TX_FEE);

        let now = now_secs();
        // Genesis: zero parent at GENESIS_HEIGHT. This previously used height 1
        // with a zero parent — a shape no real chain can have, and now rejected
        // by the origin rule. It was chosen because genesis paid no subsidy and
        // produced a zero-value coinbase that failed U8; genesis is now paid
        // like any other block, so the real shape validates.
        let block = propose_block(
            &[tx],
            Hash256::ZERO,
            noble_core::constants::GENESIS_HEIGHT,
            now,
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
            None,
        )
        .unwrap();

        let ctx = noble_core::BlockValidationContext {
            chain_id: test_chain_id(),
            time_context: noble_core::TimeContext::RealTime { wall_clock: now },
            parent: None,
            validator_list: &[val_pub],
        };
        assert!(noble_core::validate_block(&block, &ctx).is_ok());
    }

    // --- Stage 1b: defensive proposal (resolvability, maturity, final size) ---

    /// Per-outpoint lookup: resolves only registered outpoints, each with a
    /// creation height for the maturity gate.
    struct MapLookup(std::collections::HashMap<OutPoint, (u64, u64)>); // op → (value, created_height)
    impl UtxoValueLookup for MapLookup {
        fn utxo_value(&self, op: &OutPoint) -> Option<u64> {
            self.0.get(op).map(|&(v, _)| v)
        }
        fn utxo_spendable_value(&self, op: &OutPoint, at_height: u64) -> Option<u64> {
            self.0.get(op).and_then(|&(v, created)| {
                if at_height >= created + noble_core::COINBASE_MATURITY { Some(v) } else { None }
            })
        }
    }

    /// Build a signed transfer-style tx spending exactly `prev`, paying `out`
    /// to its own address (so its output is spendable by an in-block child).
    fn make_tx_spending(prev: OutPoint, out: u64) -> (Transaction, NoblePrivateKey, Vec<u8>) {
        use noble_core::{NobleAddress, TxIn, TxOut};
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let addr = NobleAddress::Noble(noble_crypto::NoblePublicKey::Secp256k1(pk.clone()));
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_TRANSFER,
            inputs: vec![TxIn { prev_output: prev }],
            outputs: vec![TxOut { value: out, address: addr }],
            checksum: Hash256::ZERO,
            timestamp: now_secs(),
            issuer_sig: SignatureEnvelope { scheme_id: SCHEME_SECP256K1, public_key: pk.clone(), signature: vec![] },
            additional_sigs: vec![],
            declared_cosigners: Vec::new(),
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        (tx, priv_key, pk)
    }

    #[test]
    fn propose_skips_tx_with_missing_input() {
        let (val_priv, val_pub) = make_validator();
        let known = OutPoint { txid: Hash256::from_bytes([1u8; 32]), vout: 0 };
        let unknown = OutPoint { txid: Hash256::from_bytes([2u8; 32]), vout: 0 };
        // Zero-fee (output == input value) so no fee-distribution tx is added —
        // keeps the tx_count deterministic (coinbase + included user txs).
        let (tx_ok, _, _) = make_tx_spending(known.clone(), 1_000_000);
        let (tx_bad, _, _) = make_tx_spending(unknown, 1_000_000);

        // Lookup resolves only `known`, mature at height 10 (created 0, +3).
        let lookup = MapLookup([(known, (1_000_000u64, 0u64))].into_iter().collect());
        let block = propose_block(
            &[tx_ok, tx_bad], Hash256::ZERO, 10, now_secs(), test_chain_id(),
            &val_priv, &val_pub, MAX_BLOCK_SIZE, &lookup, None,
        ).unwrap();

        // coinbase + tx_ok only; tx_bad's input was unresolvable → skipped.
        assert_eq!(block.header.tx_count, 2, "tx with missing input must be skipped");
    }

    #[test]
    fn propose_skips_immature_input() {
        let (val_priv, val_pub) = make_validator();
        let op = OutPoint { txid: Hash256::from_bytes([3u8; 32]), vout: 0 };
        let (tx, _, _) = make_tx_spending(op.clone(), 500_000);
        // Output created at height 9; proposing block 10 → 10 < 9+3 → immature.
        let lookup = MapLookup([(op, (1_000_000u64, 9u64))].into_iter().collect());
        let block = propose_block(
            &[tx], Hash256::ZERO, 10, now_secs(), test_chain_id(),
            &val_priv, &val_pub, MAX_BLOCK_SIZE, &lookup, None,
        ).unwrap();
        assert_eq!(block.header.tx_count, 1, "tx spending an immature output must be skipped (coinbase only)");
    }

    #[test]
    fn propose_allows_intra_block_chain() {
        let (val_priv, val_pub) = make_validator();
        let on_chain = OutPoint { txid: Hash256::from_bytes([4u8; 32]), vout: 0 };
        // Zero-fee throughout (no fee-distribution tx). Parent spends the
        // on-chain 1_000_000 UTXO into a 1_000_000 output (vout 0).
        let (parent, _, _) = make_tx_spending(on_chain.clone(), 1_000_000);
        let parent_id = parent.compute_tx_id(test_chain_id()).unwrap();
        // Child spends the parent's output (vout 0) — not on-chain, resolved in-block.
        let parent_out = OutPoint { txid: parent_id, vout: 0 };
        let (child, _, _) = make_tx_spending(parent_out, 1_000_000);

        let lookup = MapLookup([(on_chain, (1_000_000u64, 0u64))].into_iter().collect());
        let block = propose_block(
            &[parent, child], Hash256::ZERO, 10, now_secs(), test_chain_id(),
            &val_priv, &val_pub, MAX_BLOCK_SIZE, &lookup, None,
        ).unwrap();
        // coinbase + parent + child: the child's input resolved via in_block_value.
        assert_eq!(block.header.tx_count, 3, "intra-block CPFP child must be included");
    }

    #[test]
    fn propose_final_block_respects_max_size() {
        // A normal proposal must never assemble a block larger than max_size,
        // even though the coinbase is prepended after selection. With a max_size
        // smaller than even the coinbase, the proposer fails closed (Err) rather
        // than emit an oversized block.
        let (val_priv, val_pub) = make_validator();
        let tx = make_test_tx(b"sz", MIN_TX_FEE);
        let result = propose_block(
            &[tx], Hash256::ZERO, 1, now_secs(), test_chain_id(),
            &val_priv, &val_pub, 50, &FixedUtxoLookup(2_000_000), None,
        );
        assert!(result.is_err(), "max_size below coinbase size must fail closed, not emit an oversized block");
    }
}
