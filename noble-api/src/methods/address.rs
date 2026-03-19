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

        // Subtract immature coinbase UTXOs from available balance.
        let chain_height = storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0);
        let immature: u64 = storage
            .get_address_utxos(&addr)
            .unwrap_or_default()
            .iter()
            .filter(|(_, e)| e.is_coinbase && !e.is_mature(chain_height))
            .map(|(_, e)| e.value)
            .sum();

        // pending = mempool debits targeting this address bucket
        let pending = {
            let mempool = self.mempool.lock();
            mempool.pending_debit_for_address(&addr)
        };
        let available = balance.saturating_sub(pending).saturating_sub(immature);

        // Count address history entries
        let tx_count = storage
            .count_address_history(&addr)
            .unwrap_or(0);

        Ok(AddressBalanceResponse {
            public_key: address,
            balance,
            available,
            pending,
            tx_count,
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

        // Get total count
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

    async fn get_address_utxos(
        &self,
        address: String,
    ) -> Result<AddressUtxosResponse, ErrorObjectOwned> {
        let addr = parse_address(&address)?;
        let storage = self.storage.read();
        let utxos = storage.get_address_utxos(&addr).map_err(ApiError::from)?;

        // Exclude immature coinbase UTXOs — clients should never see
        // unspendable coins in the UTXO set (prevents NE-618 at source).
        let chain_height = storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0);

        let mut immature_count: usize = 0;
        let mut immature_value: u64 = 0;

        let entries: Vec<UtxoResponse> = utxos
            .iter()
            .filter(|(_, entry)| {
                if !entry.is_mature(chain_height) {
                    immature_count += 1;
                    immature_value += entry.value;
                    false
                } else {
                    true
                }
            })
            .map(|(outpoint, entry)| UtxoResponse {
                txid: hash_to_hex(&outpoint.txid),
                vout: outpoint.vout,
                value: entry.value,
                height: entry.height,
                is_coinbase: entry.is_coinbase,
            })
            .collect();

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
