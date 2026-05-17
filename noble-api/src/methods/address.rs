// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Address-related RPC methods: getAddressBalance, getAddressHistory, validateAddress.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_core::NobleAddress;
use noble_crypto::NoblePublicKey;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait AddressApi {
    /// Get the balance for an address.
    /// Accepts hex-encoded NOBLE public keys or Bitcoin addresses (bc1q, 1..., bc1p).
    #[method(name = "getAddressBalance")]
    async fn get_address_balance(
        &self,
        address: String,
    ) -> Result<AddressBalanceResponse, ErrorObjectOwned>;

    /// Get paginated transaction history for an address.
    #[method(name = "getAddressHistory")]
    async fn get_address_history(
        &self,
        address: String,
        page: u32,
        limit: u32,
    ) -> Result<AddressHistoryResponse, ErrorObjectOwned>;

    /// Get unspent transaction outputs (UTXOs) for an address.
    ///
    /// Paginated since open-node hardening (audit follow-up #7). Default
    /// page size 256, server-enforced max 256. Caller supplies `limit`
    /// (clamped) and `offset` to walk longer histories.
    #[method(name = "getAddressUtxos")]
    async fn get_address_utxos(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<AddressUtxosResponse, ErrorObjectOwned>;

    /// Validate whether a string is a valid NOBLE or Bitcoin address.
    #[method(name = "validateAddress")]
    async fn validate_address(
        &self,
        address: String,
    ) -> Result<ValidateAddressResponse, ErrorObjectOwned>;

    /// Get pending (mempool) transactions for an address.
    /// Separate from confirmed history — call both for a complete view.
    #[method(name = "getAddressPending")]
    async fn get_address_pending(
        &self,
        address: String,
    ) -> Result<AddressPendingResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> AddressApiServer for Arc<ApiState<S>> {
    async fn get_address_balance(
        &self,
        address: String,
    ) -> Result<AddressBalanceResponse, ErrorObjectOwned> {
        let addr = parse_address(&address)?;

        let storage = self.storage.read();
        let balance = storage.get_balance(&addr).map_err(ApiError::from)?;

        // Scan UTXOs for maturity info.
        let chain_height = storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0);
        let all_utxos = storage.get_address_utxos(&addr).unwrap_or_default();
        let mut immature_count: usize = 0;
        let mut immature_value: u64 = 0;
        let mut utxo_count: usize = 0;
        for (_, entry) in &all_utxos {
            if entry.is_mature(chain_height) {
                utxo_count += 1;
            } else {
                immature_count += 1;
                immature_value += entry.value;
            }
        }

        // Pending: net debit + change + per-tx breakdown
        let (pending, pending_change, pending_transactions) = {
            let mempool = self.mempool.lock();
            let net = mempool.pending_debit_for_address(&addr);
            let change = mempool.pending_change_for_address(&addr);
            let summaries: Vec<PendingTxResponse> = mempool.pending_tx_summaries(&addr)
                .into_iter()
                .map(|s| PendingTxResponse {
                    tx_id: hex::encode(s.tx_id.as_bytes()),
                    sent: s.outputs_to_others,
                    change: s.outputs_to_self,
                    fee: s.fee,
                    net_debit: s.net_debit,
                    confirmation_status: "pending".to_string(),
                })
                .collect();
            (net, change, summaries)
        };
        let available = balance.saturating_sub(pending).saturating_sub(immature_value);

        // Count address history entries
        let tx_count = storage
            .count_address_history(&addr)
            .unwrap_or(0);

        Ok(AddressBalanceResponse {
            public_key: address,
            balance,
            available,
            pending,
            pending_change,
            tx_count,
            utxo_count,
            immature_count,
            immature_value,
            pending_transactions,
        })
    }

    async fn get_address_history(
        &self,
        address: String,
        page: u32,
        limit: u32,
    ) -> Result<AddressHistoryResponse, ErrorObjectOwned> {
        let addr = parse_address(&address)?;

        let clamped_limit = limit.min(100);
        let storage = self.storage.read();
        let tx_ids = storage
            .get_address_history(&addr, page, clamped_limit)
            .map_err(ApiError::from)?;

        let total = storage
            .count_address_history(&addr)
            .unwrap_or(0);

        Ok(AddressHistoryResponse {
            public_key: address,
            transactions: tx_ids.iter().map(hash_to_hex).collect(),
            total,
            page,
            limit: clamped_limit,
        })
    }

    async fn get_address_pending(
        &self,
        address: String,
    ) -> Result<AddressPendingResponse, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let mempool = self.mempool.lock();
        let summaries = mempool.pending_tx_summaries(&addr);
        let entries: Vec<PendingTxResponse> = summaries.iter().map(|s| PendingTxResponse {
            tx_id: hex::encode(s.tx_id.as_bytes()),
            sent: s.outputs_to_others,
            change: s.outputs_to_self,
            fee: s.fee,
            net_debit: s.net_debit,
            confirmation_status: "pending".to_string(),
        }).collect();
        Ok(AddressPendingResponse {
            address,
            count: entries.len(),
            transactions: entries,
        })
    }

    async fn get_address_utxos(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<AddressUtxosResponse, ErrorObjectOwned> {
        const DEFAULT_PAGE: u32 = 256;
        const MAX_PAGE: u32 = 256;
        let limit = limit.unwrap_or(DEFAULT_PAGE).min(MAX_PAGE) as usize;
        let offset = offset.unwrap_or(0) as usize;

        let addr = parse_address(&address)?;
        let storage = self.storage.read();
        let utxos = storage.get_address_utxos(&addr).map_err(ApiError::from)?;
        let total_utxos = utxos.len();

        let chain_height = storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0);

        // Check mempool for outpoints consumed by pending transactions.
        let mempool = self.mempool.lock();

        let mut immature_count: usize = 0;
        let mut immature_value: u64 = 0;

        // Walk ALL committed UTXOs to compute immature totals (small data,
        // fast scan), but only materialize the requested page.
        let mut all_entries: Vec<UtxoResponse> = Vec::with_capacity(utxos.len());
        for (outpoint, entry) in utxos.iter() {
            let status = if !entry.is_mature(chain_height) {
                immature_count += 1;
                immature_value += entry.value;
                "immature"
            } else if mempool.is_outpoint_spent(outpoint) {
                "pending_spend"
            } else {
                "available"
            };
            all_entries.push(UtxoResponse {
                txid: hash_to_hex(&outpoint.txid),
                vout: outpoint.vout,
                value: entry.value,
                height: entry.height,
                is_coinbase: entry.is_coinbase,
                status: status.to_string(),
            });
        }

        // Include unconfirmed mempool outputs (change from pending txs) for this address.
        let addr_wire = addr.to_wire_bytes();
        for (outpoint, value) in mempool.outputs_for_address(&addr_wire) {
            all_entries.push(UtxoResponse {
                txid: hash_to_hex(&outpoint.txid),
                vout: outpoint.vout,
                value,
                height: 0,
                is_coinbase: false,
                status: "unconfirmed".to_string(),
            });
        }
        drop(mempool);

        // Apply pagination AFTER assembly so immature totals reflect the
        // whole set, not just the page.
        let total_returned = all_entries.len();
        let page: Vec<UtxoResponse> = all_entries
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();
        if total_returned > limit + offset {
            tracing::debug!(
                task = "address_utxos",
                "returning page of {} of {} total UTXOs (limit={}, offset={})",
                page.len(),
                total_returned,
                limit,
                offset
            );
        }
        let _ = total_utxos; // retained for clarity; immature counts use the live walk

        Ok(AddressUtxosResponse {
            address,
            utxos: page,
            immature_count,
            immature_value,
        })
    }

    async fn validate_address(
        &self,
        address: String,
    ) -> Result<ValidateAddressResponse, ErrorObjectOwned> {
        // Try parse_address — accepts both Bitcoin and NOBLE formats
        match parse_address(&address) {
            Ok(addr) => Ok(ValidateAddressResponse {
                valid: true,
                scheme_id: match addr {
                    NobleAddress::Noble(ref pk) => Some(pk.scheme_id()),
                    _ => None,
                },
                address_type: Some(addr.address_type().to_string()),
            }),
            Err(_) => {
                // Also try raw hex as NoblePublicKey for backwards compat
                let wire_bytes = match hex::decode(&address) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(ValidateAddressResponse {
                            valid: false,
                            scheme_id: None,
                            address_type: None,
                        })
                    }
                };
                match NoblePublicKey::from_wire_bytes(&wire_bytes) {
                    Ok(pk) => Ok(ValidateAddressResponse {
                        valid: true,
                        scheme_id: Some(pk.scheme_id()),
                        address_type: Some(
                            NobleAddress::Noble(pk).address_type().to_string(),
                        ),
                    }),
                    Err(_) => Ok(ValidateAddressResponse {
                        valid: false,
                        scheme_id: None,
                        address_type: None,
                    }),
                }
            }
        }
    }
}
