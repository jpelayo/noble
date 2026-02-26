// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node-related RPC methods: getNodeInfo, rotateTotpSecret, gateway info/rotation.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_core::{PROTOCOL_VERSION, SOFTWARE_VERSION};
use noble_storage::StorageEngine;

use crate::auth::TotpValidator;
use crate::error::ApiError;
use crate::state::{ApiState, NodeIdentityData};
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait NodeApi {
    /// Get general node information.
    #[method(name = "getNodeInfo")]
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned>;

    /// Get the API version and method count.
    #[method(name = "getApiVersion")]
    async fn get_api_version(&self) -> Result<ApiVersionResponse, ErrorObjectOwned>;

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

    /// Get the current IP access control list.
    #[method(name = "getAllowedIps")]
    async fn get_allowed_ips(&self) -> Result<AllowedIpsResponse, ErrorObjectOwned>;

    /// Update the IP access control list at runtime.
    ///
    /// Note: switching between empty (localhost-only) and non-empty (remote
    /// access) requires a node restart because the bind address changes.
    #[method(name = "setAllowedIps")]
    async fn set_allowed_ips(
        &self,
        allowed_ips: Vec<String>,
    ) -> Result<SetAllowedIpsResponse, ErrorObjectOwned>;

    /// Get current gateway fee-split configuration.
    #[method(name = "getGatewayInfo")]
    async fn get_gateway_info(&self) -> Result<GatewayInfoResponse, ErrorObjectOwned>;

    /// Rotate the gateway key to a different wallet key.
    ///
    /// The `public_key` parameter is the hex-encoded wire bytes of the new
    /// gateway key. The key must exist in the wallet keystore.
    #[method(name = "rotateGatewayKey")]
    async fn rotate_gateway_key(
        &self,
        public_key: String,
    ) -> Result<RotateGatewayKeyResponse, ErrorObjectOwned>;

    /// Get the current node identity configuration.
    #[method(name = "getNodeIdentity")]
    async fn get_node_identity(&self) -> Result<NodeIdentityResponse, ErrorObjectOwned>;

    /// Update the node identity configuration and persist to identity.json.
    #[method(name = "setNodeIdentity")]
    async fn set_node_identity(
        &self,
        node_name: String,
        org_type: String,
        org_name: Option<String>,
        node_role: String,
        contact_email: Option<String>,
        website: Option<String>,
        host_address: Option<String>,
        wants_to_validate: bool,
        wants_to_vote: bool,
    ) -> Result<SetNodeIdentityResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NodeApiServer for Arc<ApiState<S>> {
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned> {
        let uptime = self.start_time.elapsed().as_secs();
        Ok(NodeInfoResponse {
            version: SOFTWARE_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
            chain_id: self.chain_id,
            uptime_secs: uptime,
            rpc_port: self.rpc_port,
            ws_port: self.ws_port,
            p2p_port: self.p2p_port,
        })
    }

    async fn get_api_version(&self) -> Result<ApiVersionResponse, ErrorObjectOwned> {
        Ok(ApiVersionResponse {
            version: crate::API_VERSION.to_string(),
            methods: crate::API_METHOD_COUNT,
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
            let v = validator_arc.read();
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
            let mut v = validator_arc.write();
            *v = new_validator;
        }

        tracing::info!("TOTP secret rotated successfully");

        Ok(RotateTotpResponse {
            secret_base32: base32,
            otpauth_uri: uri,
        })
    }

    async fn get_allowed_ips(&self) -> Result<AllowedIpsResponse, ErrorObjectOwned> {
        let (allowed_ips, remote_access_enabled) = match &self.ip_filter {
            Some(filter) => (filter.list(), filter.has_remote_access()),
            None => (Vec::new(), false),
        };
        Ok(AllowedIpsResponse {
            allowed_ips,
            remote_access_enabled,
        })
    }

    async fn get_gateway_info(&self) -> Result<GatewayInfoResponse, ErrorObjectOwned> {
        let gw = self.gateway_key.read();
        let (enabled, gateway_hex, source) = match &*gw {
            Some(key) => {
                let hex = ::hex::encode(key);
                let source = if self.gateway_key_path.is_some() {
                    "config_file"
                } else {
                    "wallet_auto"
                };
                (true, Some(hex), source.to_string())
            }
            None => (false, None, "none".to_string()),
        };
        Ok(GatewayInfoResponse {
            enabled,
            gateway_key: gateway_hex,
            key_source: source,
        })
    }

    async fn rotate_gateway_key(
        &self,
        public_key: String,
    ) -> Result<RotateGatewayKeyResponse, ErrorObjectOwned> {
        // Parse and validate the new key.
        let new_key_bytes = ::hex::decode(&public_key)
            .map_err(|_| ApiError::InvalidAddress("invalid hex string".into()))?;

        // Verify the key exists in the wallet keystore.
        let pk = noble_crypto::NoblePublicKey::from_wire_bytes(&new_key_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;
        {
            let ks = self.wallet_keystore.lock();
            let keys = ks
                .list_keys()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            if !keys.iter().any(|k| k == &pk) {
                return Err(ApiError::InvalidParam(
                    "public key not found in wallet keystore".into(),
                )
                .into());
            }
        }

        // Update the in-memory gateway key.
        {
            let mut gw = self.gateway_key.write();
            *gw = Some(new_key_bytes.clone());
        }

        // Persist to disk if a key_path is configured.
        let persisted = if let Some(path) = &self.gateway_key_path {
            let tmp = path.with_extension("tmp");
            if let Err(e) = std::fs::write(&tmp, public_key.as_bytes()) {
                tracing::warn!("Failed to write gateway key tmp: {e}");
                false
            } else if let Err(e) = std::fs::rename(&tmp, path) {
                tracing::warn!("Failed to rename gateway key file: {e}");
                false
            } else {
                tracing::info!("Gateway key rotated and persisted to {}", path.display());
                true
            }
        } else {
            tracing::info!("Gateway key rotated (in-memory only, no key_path configured)");
            false
        };

        Ok(RotateGatewayKeyResponse {
            success: true,
            new_gateway_key: public_key,
            persisted,
        })
    }

    async fn set_allowed_ips(
        &self,
        allowed_ips: Vec<String>,
    ) -> Result<SetAllowedIpsResponse, ErrorObjectOwned> {
        let filter = self.ip_filter.as_ref().ok_or_else(|| {
            ApiError::InvalidParam(
                "IP filter not initialized. Add allowed_ips to [api] config and restart.".into(),
            )
        })?;

        let was_remote = filter.has_remote_access();

        filter
            .update(&allowed_ips)
            .map_err(ApiError::InvalidParam)?;

        let is_remote = filter.has_remote_access();

        // Warn if the bind address mode changed (requires restart).
        let message = if was_remote != is_remote {
            format!(
                "Allowed IPs updated ({} entries). Note: bind address change ({}→{}) requires node restart to take effect.",
                allowed_ips.len(),
                if was_remote { "0.0.0.0" } else { "127.0.0.1" },
                if is_remote { "0.0.0.0" } else { "127.0.0.1" },
            )
        } else {
            format!("Allowed IPs updated ({} entries)", allowed_ips.len())
        };

        tracing::info!(task = "ip_filter", "{message}");

        Ok(SetAllowedIpsResponse {
            success: true,
            message,
        })
    }

    async fn get_node_identity(&self) -> Result<NodeIdentityResponse, ErrorObjectOwned> {
        let id = self.node_identity.read();
        Ok(NodeIdentityResponse {
            node_name: id.node_name.clone(),
            org_type: id.org_type.clone(),
            org_name: id.org_name.clone(),
            node_role: id.node_role.clone(),
            contact_email: id.contact_email.clone(),
            website: id.website.clone(),
            host_address: id.host_address.clone(),
            wants_to_validate: id.wants_to_validate,
            wants_to_vote: id.wants_to_vote,
        })
    }

    async fn set_node_identity(
        &self,
        node_name: String,
        org_type: String,
        org_name: Option<String>,
        node_role: String,
        contact_email: Option<String>,
        website: Option<String>,
        host_address: Option<String>,
        wants_to_validate: bool,
        wants_to_vote: bool,
    ) -> Result<SetNodeIdentityResponse, ErrorObjectOwned> {
        if node_name.trim().is_empty() {
            return Err(ApiError::InvalidParam("node_name must not be empty".into()).into());
        }

        let new_identity = NodeIdentityData {
            node_name,
            org_type,
            org_name: org_name.unwrap_or_default(),
            node_role,
            contact_email: contact_email.unwrap_or_default(),
            website: website.unwrap_or_default(),
            host_address: host_address.unwrap_or_default(),
            wants_to_validate,
            wants_to_vote,
        };

        // Persist to identity.json atomically.
        if let Some(path) = &self.identity_path {
            let json = serde_json::to_string_pretty(&new_identity)
                .map_err(|e| ApiError::Internal(format!("serialize identity: {e}")))?;
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, json.as_bytes())
                .map_err(|e| ApiError::Internal(format!("write identity tmp: {e}")))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| ApiError::Internal(format!("rename identity file: {e}")))?;
            tracing::info!(task = "identity", "Node identity persisted to {}", path.display());
        }

        // Update in-memory state.
        {
            let mut id = self.node_identity.write();
            *id = new_identity;
        }

        Ok(SetNodeIdentityResponse { success: true })
    }
}
