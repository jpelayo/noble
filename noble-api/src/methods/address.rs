// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Address-related RPC methods: getAddressBalance, getAddressHistory, validateAddress.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_crypto::NoblePublicKey;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait AddressApi {
    /// Get the balance for an address (hex-encoded wire-format public key).
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

    /// Validate whether a hex string is a valid NOBLE address.
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
        let pubkey = parse_pubkey(&address)?;

        let storage = self.storage.read();
        let balance = storage.get_balance(&pubkey).map_err(ApiError::from)?;

        // pending = mempool debits for this address (not yet committed)
        let pending = {
            let mempool = self.mempool.lock();
            mempool.pending_debit(&pubkey)
        };
        let available = balance.saturating_sub(pending);

        // Count address history entries
        let tx_count = storage
            .get_address_history(&pubkey, 0, 0)
            .map(|ids| ids.len() as u64)
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
        let pubkey = parse_pubkey(&address)?;

        let clamped_limit = limit.min(100);
        let storage = self.storage.read();
        let tx_ids = storage
            .get_address_history(&pubkey, page, clamped_limit)
            .map_err(ApiError::from)?;

        // Get total count (pass limit 0 to get all for counting, or use a separate method)
        let total = storage
            .get_address_history(&pubkey, 0, 0)
            .map(|ids| ids.len() as u64)
            .unwrap_or(0);

        Ok(AddressHistoryResponse {
            public_key: address,
            transactions: tx_ids.iter().map(hash_to_hex).collect(),
            total,
            page,
            limit: clamped_limit,
        })
    }

    async fn validate_address(
        &self,
        address: String,
    ) -> Result<ValidateAddressResponse, ErrorObjectOwned> {
        let wire_bytes = match hex::decode(&address) {
            Ok(b) => b,
            Err(_) => {
                return Ok(ValidateAddressResponse {
                    valid: false,
                    scheme_id: None,
                })
            }
        };

        match NoblePublicKey::from_wire_bytes(&wire_bytes) {
            Ok(pk) => Ok(ValidateAddressResponse {
                valid: true,
                scheme_id: Some(pk.scheme_id()),
            }),
            Err(_) => Ok(ValidateAddressResponse {
                valid: false,
                scheme_id: None,
            }),
        }
    }
}
