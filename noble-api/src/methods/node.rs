// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node-related RPC methods: getNodeInfo, rotateTotpSecret.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_core::{PROTOCOL_VERSION, SOFTWARE_VERSION};
use noble_storage::StorageEngine;

use crate::auth::TotpValidator;
use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait NodeApi {
    /// Get general node information.
    #[method(name = "getNodeInfo")]
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned>;

    /// Rotate the TOTP shared secret.
    ///
    /// Requires a valid TOTP code (SHA-256 hashed, as used for auth)
    /// from the current secret as proof of possession. On success, the
    /// old secret is replaced immediately and the new base32 secret +
    /// otpauth:// URI are returned.
    #[method(name = "rotateTotpSecret")]
    async fn rotate_totp_secret(
        &self,
        current_code_hash: String,
    ) -> Result<RotateTotpResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NodeApiServer for Arc<ApiState<S>> {
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned> {
        let uptime = self.start_time.elapsed().as_secs();
        let latest_network_version = self
            .max_network_version
            .read()
            .map(|v| v.clone())
            .unwrap_or_else(|_| SOFTWARE_VERSION.to_string());
        Ok(NodeInfoResponse {
            version: PROTOCOL_VERSION as u32,
            chain_id: self.chain_id,
            uptime_secs: uptime,
            software_version: SOFTWARE_VERSION.to_string(),
            latest_network_version,
        })
    }

    async fn rotate_totp_secret(
        &self,
        current_code_hash: String,
    ) -> Result<RotateTotpResponse, ErrorObjectOwned> {
        // Ensure TOTP is enabled.
        let validator_arc = self
            .totp_validator
            .as_ref()
            .ok_or_else(|| ApiError::InvalidParam("TOTP auth is not enabled".into()))?;

        // Verify the current code.
        {
            let v = validator_arc
                .read()
                .map_err(|e| ApiError::Internal(format!("totp lock: {e}")))?;
            if !v.validate_hash(&current_code_hash) {
                return Err(ApiError::AuthRequired.into());
            }
        }

        // Generate a new secret.
        let (new_validator, base32, uri) = TotpValidator::rotate().map_err(ApiError::Internal)?;

        // Persist the new secret atomically (write to .tmp, then rename).
        if let Some(path) = &self.totp_secret_path {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, base32.as_bytes())
                .map_err(|e| ApiError::Internal(format!("write secret tmp: {e}")))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| ApiError::Internal(format!("rename secret file: {e}")))?;
        }

        // Swap the in-memory validator.
        {
            let mut v = validator_arc
                .write()
                .map_err(|e| ApiError::Internal(format!("totp lock: {e}")))?;
            *v = new_validator;
        }

        tracing::info!("TOTP secret rotated successfully");

        Ok(RotateTotpResponse {
            secret_base32: base32,
            otpauth_uri: uri,
        })
    }
}
