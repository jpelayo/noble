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

    /// Get all unspent transaction outputs (UTXOs) for an address.
    #[method(name = "getAddressUtxos")]
    async fn get_address_utxos(
        &self,
        address: String,
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
    ) -> Result<AddressUtxosResponse, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let storage = self.storage.read();
        let utxos = storage.get_address_utxos(&addr).map_err(ApiError::from)?;

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

        // Return ALL UTXOs with lifecycle status so the client has full visibility.
        let entries: Vec<UtxoResponse> = utxos
            .iter()
            .map(|(outpoint, entry)| {
                let status = if !entry.is_mature(chain_height) {
                    immature_count += 1;
                    immature_value += entry.value;
                    "immature"
                } else if mempool.is_outpoint_spent(outpoint) {
                    "pending_spend"
                } else {
                    "available"
                };
                UtxoResponse {
                    txid: hash_to_hex(&outpoint.txid),
                    vout: outpoint.vout,
                    value: entry.value,
                    height: entry.height,
                    is_coinbase: entry.is_coinbase,
                    status: status.to_string(),
                }
            })
            .collect();

        // Include unconfirmed mempool outputs (change from pending txs) for this address.
        let addr_wire = addr.to_wire_bytes();
        let mut entries = entries;
        for (outpoint, value) in mempool.outputs_for_address(&addr_wire) {
            entries.push(UtxoResponse {
                txid: hash_to_hex(&outpoint.txid),
                vout: outpoint.vout,
                value,
                height: 0,
                is_coinbase: false,
                status: "unconfirmed".to_string(),
            });
        }

        drop(mempool);

        Ok(AddressUtxosResponse {
            address,
            utxos: entries,
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
