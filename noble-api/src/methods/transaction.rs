// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction-related RPC methods: submitTransaction, getTransaction, getTransactionStatus.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_codec::NobleCbor;
use noble_core::Transaction;
use noble_crypto::Hash256;
use noble_mempool::{UtxoLookup, ChainLookup};
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

// ---------------------------------------------------------------------------
// Adapter structs for mempool admission
// ---------------------------------------------------------------------------

/// Adapter that implements `ChainLookup` by querying the storage engine.
struct StorageChainLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> ChainLookup for StorageChainLookup<'_, S> {
    fn is_confirmed(&self, tx_id: &Hash256) -> bool {
        self.storage.has_transaction(tx_id).unwrap_or(false)
    }
}

/// Adapter that implements `UtxoLookup` by querying the storage engine.
struct StorageUtxoLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> UtxoLookup for StorageUtxoLookup<'_, S> {
    fn get_utxo(&self, outpoint: &noble_core::OutPoint) -> Option<noble_core::UtxoEntry> {
        // Full entry: admission needs `address` to enforce input ownership (C1).
        match self.storage.get_utxo(outpoint) {
            Ok(Some(entry)) => Some(entry),
            _ => None,
        }
    }
}

/// Resolve each input's spent UTXO (value + owner address) from storage,
/// compute the implicit fee, and enrich the response in place.
///
/// - Sets `resp.fee = Some(Σinputs − Σoutputs)` when every input resolves
///   (coinbase is skipped — no fee).
/// - For non-transfer types, `resp.inputs` is populated (1:1 with
///   `tx.inputs`), so we also write each input's `value` + `address`.
///   Transfers keep `resp.inputs = []` for privacy but still get `fee`.
///
/// The tx-detail "Balance Changes" ledger needs the per-input address+value
/// to attribute who paid what; the on-chain receipt path previously left
/// `fee = None` and never resolved inputs at all.
pub(crate) fn resolve_inputs_and_fee<S: StorageEngine>(
    storage: &S,
    tx: &Transaction,
    resp: &mut TransactionResponse,
    // Per-request memo of previously-read source transactions: within a
    // block view many inputs share a prev tx, and each get_transaction is
    // a full CBOR decode — the memo collapses that to one read per source.
    memo: &mut std::collections::HashMap<Hash256, Transaction>,
) {
    if tx.is_coinbase() {
        return;
    }
    let mut input_total: u64 = 0;
    let mut all_resolved = true;
    for (i, inp) in tx.inputs.iter().enumerate() {
        let prev_tx = match memo.entry(inp.prev_output.txid) {
            std::collections::hash_map::Entry::Occupied(e) => Some(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(v) => {
                match storage.get_transaction(&inp.prev_output.txid) {
                    Ok(t) => Some(v.insert(t)),
                    Err(e) => {
                        tracing::warn!(
                            prev_txid = %hex::encode(inp.prev_output.txid.as_bytes()),
                            "input resolution: prev tx read failed \
                             (pruned storage or corruption?): {e}"
                        );
                        None
                    }
                }
            }
        };
        match prev_tx.and_then(|p| p.outputs.get(inp.prev_output.vout as usize)) {
            Some(out) => {
                input_total = input_total.saturating_add(out.value);
                // Enrich the matching response input when present (index
                // alignment holds because non-transfer inputs are mapped
                // 1:1 in tx_to_response).
                if let Some(ri) = resp.inputs.get_mut(i) {
                    ri.value = Some(out.value);
                    ri.address = Some(out.address.to_display_address());
                }
            }
            None => {
                tracing::debug!(
                    vout = inp.prev_output.vout,
                    "input resolution: prev tx missing or vout out of range"
                );
                all_resolved = false;
            }
        }
    }
    if all_resolved {
        resp.fee = Some(input_total.saturating_sub(tx.total_output_value()));
    }
}

/// Resolve a PENDING transaction's inputs from the live UTXO set — a
/// mempool tx's inputs are by definition still unspent, so `get_utxo` is a
/// cheap point lookup (no prev-tx decode). Fee is NOT computed here — the
/// mempool entry already carries the exact fee.
pub(crate) fn resolve_inputs_from_utxos<S: StorageEngine>(
    storage: &S,
    tx: &Transaction,
    resp: &mut TransactionResponse,
) {
    for (i, inp) in tx.inputs.iter().enumerate() {
        match storage.get_utxo(&inp.prev_output) {
            Ok(Some(entry)) => {
                if let Some(ri) = resp.inputs.get_mut(i) {
                    ri.value = Some(entry.value);
                    ri.address = Some(entry.address.to_display_address());
                }
            }
            Ok(None) => {
                // Raced a commit (input just got spent) — leave unresolved;
                // the next query hits the on-chain path.
                tracing::debug!("pending input resolution: UTXO already spent/absent");
            }
            Err(e) => {
                tracing::warn!("pending input resolution: UTXO read failed: {e}");
            }
        }
    }
}

#[rpc(server, namespace = "noble")]
pub trait TransactionApi {
    /// Submit a hex-encoded CBOR transaction to the mempool.
    #[method(name = "submitTransaction")]
    async fn submit_transaction(
        &self,
        tx_hex: String,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned>;

    /// Get a transaction by its hex-encoded tx_id.
    /// Checks mempool first, then on-chain storage.
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_id: String)
        -> Result<TransactionResponse, ErrorObjectOwned>;

    /// Get the status of a transaction (pending, confirmed, or unknown).
    #[method(name = "getTransactionStatus")]
    async fn get_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<TransactionStatusResponse, ErrorObjectOwned>;

    /// Get a full receipt for a transaction including block location and confirmations.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        tx_id: String,
    ) -> Result<TransactionReceiptResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> TransactionApiServer for Arc<ApiState<S>> {
    async fn submit_transaction(
        &self,
        tx_hex: String,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // Reject oversized hex before allocation (OOM prevention — C2 audit fix).
        // MAX_TX_SIZE is 8KB; hex is 2 chars per byte, plus margin for whitespace.
        if tx_hex.len() > noble_core::MAX_TX_SIZE * 2 + 64 {
            return Err(ApiError::TxTooLarge(
                format!("Transaction hex too large ({} chars, max {})", tx_hex.len(), noble_core::MAX_TX_SIZE * 2),
            ).into());
        }

        // Decode hex to bytes
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|_| ApiError::TxRejected("invalid hex encoding".into()))?;

        // Decode CBOR to Transaction
        let tx = Transaction::from_cbor(&tx_bytes)
            .map_err(|e| ApiError::TxRejected(format!("CBOR decode failed: {e}")))?;

        // Current time for mempool admission
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check fee rate against this node's minimum preference.
        // This prevents txs from entering the mempool only to be ignored at proposal time.
        let node_min_rate = self.min_fee_rate.load(std::sync::atomic::Ordering::Relaxed);
        if node_min_rate > noble_core::MIN_RELAY_FEE_RATE && !tx.is_coinbase() {
            let storage = self.storage.read();
            let mut input_total: u64 = 0;
            let mut all_resolved = true;
            for inp in &tx.inputs {
                match storage.get_utxo(&inp.prev_output) {
                    Ok(Some(entry)) => input_total += entry.value,
                    Ok(None) => { all_resolved = false; break; }
                    Err(e) => {
                        tracing::warn!(task = "submit_tx", "fee check: UTXO lookup error: {e}");
                        all_resolved = false;
                        break;
                    }
                }
            }
            if all_resolved {
                let output_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
                let fee = input_total.saturating_sub(output_total);
                let size = tx_bytes.len() as u64;
                let fee_rate = if size > 0 { fee / size } else { 0 };
                if fee_rate < node_min_rate {
                    return Err(ApiError::TxRejected(format!(
                        "Fee rate too low for this node: {} groats/byte (node minimum: {}). \
                         Increase the fee or connect to a node with a lower minimum fee rate.",
                        fee_rate, node_min_rate
                    )).into());
                }
            }
        }

        // Admit to mempool with storage-backed lookups
        let tx_id = {
            let storage = self.storage.read();
            let chain_height = storage
                .get_chain_tip()
                .ok()
                .flatten()
                .map(|t| t.height)
                .unwrap_or(0);
            let chain_lookup = StorageChainLookup { storage: &*storage };
            let utxo_lookup = StorageUtxoLookup { storage: &*storage };

            let mut mempool = self.mempool.lock();
            mempool
                .admit_with_size(&tx, now, &chain_lookup, &utxo_lookup, chain_height, Some(tx_bytes.len()))
                .map_err(|e| -> ErrorObjectOwned { ApiError::from(e).into() })?
        };

        // Broadcast to network (best-effort, log if channel is full).
        if let Err(e) = self
            .network_cmd
            .try_send(NetworkCommand::PublishTransaction(tx))
        {
            tracing::warn!(task = "tx_broadcast", %tx_id, "network broadcast dropped (channel full): {e}");
        }

        Ok(SubmitTxResponse {
            tx_id: hash_to_hex(&tx_id),
            accepted: true,
        })
    }

    async fn get_transaction(
        &self,
        tx_id: String,
    ) -> Result<TransactionResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool first — fee is pre-computed in the mempool entry.
        // Clone out of the mempool lock before touching storage: the lock
        // order is Storage(2) < Mempool(5), so storage must never be
        // acquired while the mempool lock is held.
        let pending = {
            let mempool = self.mempool.lock();
            mempool.get(&tx_id_hash).map(|entry| (entry.tx.clone(), entry.fee))
        };
        if let Some((tx, fee)) = pending {
            let mut resp = tx_to_response(&tx, &tx_id);
            resp.fee = Some(fee);
            resp.confirmation_status = Some("pending".to_string());
            resp.confirmations = None;
            // Pending inputs are still unspent — resolve value/address from
            // the live UTXO set so the tx-detail Balance Changes ledger
            // reaches full mode instead of a misleading partial view.
            let storage = self.storage.read();
            resolve_inputs_from_utxos(&*storage, &tx, &mut resp);
            return Ok(resp);
        }

        // Check on-chain storage — compute fee from UTXO inputs.
        let storage = self.storage.read();
        let tx = storage
            .get_transaction(&tx_id_hash)
            .map_err(ApiError::from)?;

        let mut resp = tx_to_response(&tx, &tx_id);
        resolve_inputs_and_fee(&*storage, &tx, &mut resp, &mut Default::default());
        // Compute confirmation status from tx location
        if let Ok((tx_height, _)) = storage.get_transaction_location(&tx_id_hash) {
            let tip = storage.get_chain_tip().ok().flatten().map(|t| t.height).unwrap_or(0);
            let confs = tip.saturating_sub(tx_height) + 1;
            resp.confirmations = Some(confs);
            resp.confirmation_status = Some(confirmation_status_label(Some(confs)));
            resp.block_height = Some(tx_height);
        }
        Ok(resp)
    }

    async fn get_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<TransactionStatusResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool
        {
            let mempool = self.mempool.lock();
            if mempool.contains(&tx_id_hash) {
                return Ok(TransactionStatusResponse {
                    tx_id,
                    status: "pending".to_string(),
                });
            }
        }

        // Check storage
        let storage = self.storage.read();
        if storage.has_transaction(&tx_id_hash).unwrap_or(false) {
            return Ok(TransactionStatusResponse {
                tx_id,
                status: "confirmed".to_string(),
            });
        }

        Ok(TransactionStatusResponse {
            tx_id,
            status: "unknown".to_string(),
        })
    }

    async fn get_transaction_receipt(
        &self,
        tx_id: String,
    ) -> Result<TransactionReceiptResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool first — pending transactions have no block info.
        // Clone out of the mempool lock before touching storage (lock order:
        // Storage(2) < Mempool(5)).
        let pending = {
            let mempool = self.mempool.lock();
            mempool.get(&tx_id_hash).map(|entry| (entry.tx.clone(), entry.fee))
        };
        if let Some((tx, fee)) = pending {
            let mut tx_resp = tx_to_response(&tx, &tx_id);
            tx_resp.fee = Some(fee);
            tx_resp.confirmation_status = Some("pending".to_string());
            tx_resp.confirmations = None;
            // Pending inputs are still unspent — resolve from the UTXO set
            // so the ledger shows the real per-address flow while pending.
            {
                let storage = self.storage.read();
                resolve_inputs_from_utxos(&*storage, &tx, &mut tx_resp);
            }
            return Ok(TransactionReceiptResponse {
                tx_id: tx_id.clone(),
                transaction: tx_resp,
                status: "pending".to_string(),
                block_height: None,
                block_hash: None,
                tx_index: None,
                confirmations: None,
            });
        }

        // Look up on-chain location
        let storage = self.storage.read();
        let (height, offset) = storage
            .get_transaction_location(&tx_id_hash)
            .map_err(ApiError::from)?;
        let tx = storage
            .get_transaction(&tx_id_hash)
            .map_err(ApiError::from)?;
        let block_hash = storage
            .get_block_hash_by_height(height)
            .map_err(ApiError::from)?;
        let tip = storage.get_chain_tip().map_err(ApiError::from)?;

        let confirmations = tip.map(|t| t.height.saturating_sub(height) + 1);

        let mut tx_resp = tx_to_response(&tx, &tx_id);
        resolve_inputs_and_fee(&*storage, &tx, &mut tx_resp, &mut Default::default());
        tx_resp.confirmations = confirmations;
        tx_resp.confirmation_status = Some(confirmation_status_label(confirmations));
        tx_resp.block_height = Some(height);

        Ok(TransactionReceiptResponse {
            tx_id: tx_id.clone(),
            transaction: tx_resp,
            status: confirmation_status_label(confirmations),
            block_height: Some(height),
            block_hash: Some(hash_to_hex(&block_hash)),
            tx_index: Some(offset),
            confirmations,
        })
    }
}
