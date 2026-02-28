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

// Bring noble_crypto into scope for validator key generation.
use noble_crypto::{SCHEME_ED25519, SCHEME_SECP256K1};

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

    /// Check whether the node has completed the setup wizard.
    ///
    /// Returns `{ setup_complete: true }` only after the full wizard (CLI or GUI)
    /// has finished. Does not require authentication.
    #[method(name = "getSetupStatus")]
    async fn get_setup_status(&self) -> Result<SetupStatusResponse, ErrorObjectOwned>;

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
        p2p_port: Option<u16>,
    ) -> Result<SetNodeIdentityResponse, ErrorObjectOwned>;

    /// Get the SHA-256 fingerprint of the active TLS certificate.
    ///
    /// Returns null when TLS is disabled.  Use this fingerprint to verify the
    /// self-signed certificate in browser trust dialogs or client configurations.
    #[method(name = "getTlsFingerprint")]
    async fn get_tls_fingerprint(&self) -> Result<TlsFingerprintResponse, ErrorObjectOwned>;

    /// Get full TLS certificate metadata: fingerprint, expiry, SANs, and mode flags.
    ///
    /// Does not require authentication — safe for the GUI status panel.
    #[method(name = "getTlsCertInfo")]
    async fn get_tls_cert_info(&self) -> Result<TlsCertInfoResponse, ErrorObjectOwned>;

    /// Regenerate the self-signed TLS certificate.
    ///
    /// Writes new `tls-cert.pem` + `tls-key.pem` to the data directory and updates
    /// the in-memory fingerprint/expiry/SANs.  **Restart the node** for the new
    /// certificate to be loaded by the TLS acceptor.
    ///
    /// `extra_sans` — additional IP addresses or DNS names for the new certificate.
    /// If omitted the default SANs (localhost, 127.0.0.1, ::1) are used.
    #[method(name = "regenerateTlsCert")]
    async fn regenerate_tls_cert(
        &self,
        extra_sans: Option<Vec<String>>,
    ) -> Result<RegenerateTlsCertResponse, ErrorObjectOwned>;

    /// Replace the TLS certificate with a CA-signed (purchased) certificate.
    ///
    /// The uploaded certificate and private key are validated (key must match cert)
    /// before any files are written, preventing an invalid cert from bricking the node.
    /// **Restart the node** to load the new certificate.
    ///
    /// `cert_pem`  — PEM-encoded leaf certificate (required).
    /// `key_pem`   — PEM-encoded private key (required).
    /// `chain_pem` — PEM-encoded intermediate chain (optional).
    #[method(name = "uploadTlsCert")]
    async fn upload_tls_cert(
        &self,
        cert_pem: String,
        key_pem: String,
        chain_pem: Option<String>,
    ) -> Result<UploadTlsCertResponse, ErrorObjectOwned>;

    /// Get validator key information: pubkey, scheme, and file path.
    ///
    /// Returns `enabled: false` when the node is running in observer mode.
    #[method(name = "getValidatorKeyInfo")]
    async fn get_validator_key_info(&self) -> Result<ValidatorKeyInfoResponse, ErrorObjectOwned>;

    /// Enable TOTP authentication for the first time.
    ///
    /// Returns the generated secret and otpauth URI for QR code scanning.
    /// Fails if TOTP is already enabled.
    #[method(name = "enableTotp")]
    async fn enable_totp(&self) -> Result<EnableTotpResponse, ErrorObjectOwned>;

    /// Get the current TOTP authentication status.
    #[method(name = "getTotpStatus")]
    async fn get_totp_status(&self) -> Result<TotpStatusResponse, ErrorObjectOwned>;

    /// Set the reward address for gateway fee splits.
    ///
    /// Accepts Bitcoin addresses (bc1q..., 1..., bc1p...) or hex-encoded NOBLE public keys.
    #[method(name = "setRewardAddress")]
    async fn set_reward_address(
        &self,
        address: String,
    ) -> Result<SetRewardAddressResponse, ErrorObjectOwned>;

    /// Get the current reward address configuration.
    #[method(name = "getRewardAddress")]
    async fn get_reward_address(&self) -> Result<GetRewardAddressResponse, ErrorObjectOwned>;

    /// Update a configuration value in noble.toml.
    ///
    /// Only a whitelist of keys is allowed:
    /// - `network.listen_port` (P2P port)
    /// - `api.rpc_port`
    /// - `api.gui_port`
    #[method(name = "setConfigValue")]
    async fn set_config_value(
        &self,
        section: String,
        key: String,
        value: String,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NodeApiServer for Arc<ApiState<S>> {
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned> {
        let uptime = self.start_time.elapsed().as_secs();
        let max_ver = self.max_network_version.read().clone();
        let latest_network_version = if max_ver.is_empty() {
            None
        } else {
            Some(max_ver)
        };

        // Calculate storage bytes by walking the data directory.
        let (storage_bytes, storage_capacity_bytes) = if let Some(ref data_dir) = self.data_dir {
            let used = dir_size(data_dir);
            let capacity = disk_capacity(data_dir);
            (Some(used), Some(capacity))
        } else {
            (None, None)
        };

        let data_dir_str = self.data_dir.as_ref().map(|d| d.display().to_string());

        Ok(NodeInfoResponse {
            version: SOFTWARE_VERSION.to_string(),
            software_version: SOFTWARE_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
            chain_id: self.chain_id,
            uptime_secs: uptime,
            rpc_port: self.rpc_port,
            ws_port: self.ws_port,
            p2p_port: self.p2p_port,
            peer_id: self.peer_id.clone(),
            latest_network_version,
            storage_bytes,
            storage_capacity_bytes,
            data_dir: data_dir_str,
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

        // F4: Rebuild CORS origins and RPC origins from the updated IP list
        // so the live servers immediately reflect the new allow-list.
        {
            let scheme = &self.cors_scheme;
            let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
            let rpc_port = self.rpc_port;
            let gui_port = self.gui_port;

            let mut cors: Vec<String> = vec![
                format!("{scheme}://127.0.0.1:{gui_port}"),
                format!("{scheme}://localhost:{gui_port}"),
                format!("{scheme}://[::1]:{gui_port}"),
            ];
            let mut rpc: Vec<String> = vec![
                format!("{scheme}://127.0.0.1:{rpc_port}"),
                format!("{scheme}://localhost:{rpc_port}"),
                format!("{scheme}://[::1]:{rpc_port}"),
                format!("{ws_scheme}://127.0.0.1:{rpc_port}"),
                format!("{ws_scheme}://localhost:{rpc_port}"),
                format!("{ws_scheme}://[::1]:{rpc_port}"),
            ];

            for ip in &allowed_ips {
                if ip.contains('/') {
                    continue; // CIDR block — not a valid HTTP origin
                }
                let gui_origin = format!("{scheme}://{ip}:{gui_port}");
                if !cors.contains(&gui_origin) {
                    cors.push(gui_origin);
                }
                let rpc_http = format!("{scheme}://{ip}:{rpc_port}");
                let rpc_ws = format!("{ws_scheme}://{ip}:{rpc_port}");
                if !rpc.contains(&rpc_http) {
                    rpc.push(rpc_http);
                }
                if !rpc.contains(&rpc_ws) {
                    rpc.push(rpc_ws);
                }
            }

            *self.allowed_cors_origins.write() = cors;
            *self.rpc_origins.write() = rpc;
        }

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

    async fn get_setup_status(&self) -> Result<SetupStatusResponse, ErrorObjectOwned> {
        let complete = self.node_identity.read().setup_complete;
        Ok(SetupStatusResponse {
            setup_complete: complete,
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
            p2p_port: id.p2p_port,
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
        p2p_port: Option<u16>,
    ) -> Result<SetNodeIdentityResponse, ErrorObjectOwned> {
        if node_name.trim().is_empty() {
            return Err(ApiError::InvalidParam("node_name must not be empty".into()).into());
        }

        let port = p2p_port.unwrap_or(8780);
        if ![8780u16, 8781, 8782].contains(&port) {
            return Err(
                ApiError::InvalidParam("p2p_port must be 8780, 8781, or 8782".into()).into(),
            );
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
            p2p_port: port,
            setup_complete: true,
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

        // A1: When the node is configured for validation, ensure a validator key exists.
        let validator_pubkey = if wants_to_validate {
            if let Some(ref identity_path) = self.identity_path {
                if let Some(data_dir) = identity_path.parent() {
                    let vkey_path = data_dir.join("validator.key");
                    if vkey_path.exists() {
                        // Already exists — just read the pubkey.
                        read_validator_pubkey(&vkey_path)
                    } else {
                        // Auto-generate.
                        match generate_validator_key(&vkey_path) {
                            Ok(pubkey) => {
                                tracing::info!(
                                    task = "setup",
                                    "Auto-generated validator key: {pubkey}"
                                );
                                Some(pubkey)
                            }
                            Err(e) => {
                                tracing::warn!(task = "setup", "Failed to generate validator key: {e}");
                                None
                            }
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(SetNodeIdentityResponse { success: true, validator_pubkey })
    }

    async fn get_tls_fingerprint(&self) -> Result<TlsFingerprintResponse, ErrorObjectOwned> {
        Ok(TlsFingerprintResponse {
            fingerprint: self.tls_fingerprint.read().clone(),
        })
    }

    async fn get_tls_cert_info(&self) -> Result<TlsCertInfoResponse, ErrorObjectOwned> {
        let fingerprint = self.tls_fingerprint.read().clone();
        let enabled = fingerprint.is_some() || self.tls_plaintext_mode;
        let tls_active = fingerprint.is_some();

        let expires_at = self.tls_expires_at.read().clone();
        let sans = self.tls_sans.read().clone();

        // Calculate days remaining using the stored Unix timestamp (avoids ISO parsing).
        let expiry_secs = self.tls_expiry_secs.read();
        let days_remaining = expiry_secs.map(|exp| {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (exp - now_secs) / 86400
        });

        Ok(TlsCertInfoResponse {
            enabled: enabled || tls_active,
            fingerprint,
            expires_at,
            days_remaining,
            sans,
            auto_generated: true, // self-signed unless uploaded via uploadTlsCert
            plaintext_mode: self.tls_plaintext_mode,
        })
    }

    async fn regenerate_tls_cert(
        &self,
        extra_sans: Option<Vec<String>>,
    ) -> Result<RegenerateTlsCertResponse, ErrorObjectOwned> {
        let regen = self.tls_regenerate.as_ref().ok_or_else(|| {
            ApiError::InvalidParam(
                "TLS regeneration is not available (TLS disabled or not configured)".into(),
            )
        })?;

        let (fingerprint, expires_at, expiry_secs, sans) = regen(extra_sans.unwrap_or_default())
            .map_err(|e| ApiError::Internal(format!("regenerate cert: {e}")))?;

        // Update in-memory state so subsequent getTlsCertInfo / getTlsFingerprint reflect
        // the new cert (the live TLS acceptor still uses the old cert until restart).
        { *self.tls_fingerprint.write() = Some(fingerprint.clone()); }
        { *self.tls_expires_at.write() = Some(expires_at.clone()); }
        { *self.tls_expiry_secs.write() = Some(expiry_secs); }
        { *self.tls_sans.write() = sans; }

        tracing::info!(
            task = "tls_cert",
            "TLS certificate regenerated — SHA-256: {fingerprint}. Restart node to apply."
        );

        Ok(RegenerateTlsCertResponse {
            fingerprint,
            expires_at,
            restart_required: true,
        })
    }

    async fn upload_tls_cert(
        &self,
        cert_pem: String,
        key_pem: String,
        chain_pem: Option<String>,
    ) -> Result<UploadTlsCertResponse, ErrorObjectOwned> {
        let upload = self.tls_upload.as_ref().ok_or_else(|| {
            ApiError::InvalidParam(
                "TLS upload is not available (TLS disabled or not configured)".into(),
            )
        })?;

        let (fingerprint, expires_at, expiry_secs, sans) = upload(cert_pem, key_pem, chain_pem)
            .map_err(|e| ApiError::InvalidParam(format!("invalid certificate: {e}")))?;

        // Update in-memory state.
        { *self.tls_fingerprint.write() = Some(fingerprint.clone()); }
        { *self.tls_expires_at.write() = Some(expires_at.clone()); }
        { *self.tls_expiry_secs.write() = Some(expiry_secs); }
        { *self.tls_sans.write() = sans.clone(); }

        tracing::info!(
            task = "tls_cert",
            "TLS certificate uploaded (CA-signed) — SHA-256: {fingerprint}. Restart node to apply."
        );

        Ok(UploadTlsCertResponse {
            fingerprint,
            expires_at,
            sans,
            auto_generated: false,
            restart_required: true,
        })
    }

    async fn get_validator_key_info(&self) -> Result<ValidatorKeyInfoResponse, ErrorObjectOwned> {
        Ok(ValidatorKeyInfoResponse {
            enabled: self.validator_pubkey.is_some(),
            pubkey_hex: self.validator_pubkey.clone(),
            scheme: self.validator_scheme.clone(),
            key_path: self.validator_key_path.clone(),
        })
    }

    async fn enable_totp(&self) -> Result<EnableTotpResponse, ErrorObjectOwned> {
        // Reject if TOTP is already enabled.
        if self.totp_validator.is_some() {
            return Err(
                ApiError::InvalidParam("TOTP is already enabled. Use rotateTotpSecret to change the secret.".into())
                    .into(),
            );
        }

        let enable_fn = self.enable_totp.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("TOTP enable callback not configured".into())
        })?;

        let (secret_base32, otpauth_uri) = enable_fn()
            .map_err(|e| ApiError::Internal(format!("enable TOTP: {e}")))?;

        tracing::info!("TOTP authentication enabled via RPC");

        Ok(EnableTotpResponse {
            secret_base32,
            otpauth_uri,
        })
    }

    async fn get_totp_status(&self) -> Result<TotpStatusResponse, ErrorObjectOwned> {
        let enabled = self.totp_validator.is_some();
        let scope = format!("{}", self.totp_scope);
        Ok(TotpStatusResponse { enabled, scope })
    }

    async fn set_reward_address(
        &self,
        address: String,
    ) -> Result<SetRewardAddressResponse, ErrorObjectOwned> {
        let trimmed = address.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::InvalidParam("address must not be empty".into()).into());
        }

        // Parse the address to validate it.
        let noble_addr = parse_address(&trimmed)?;
        let wire_bytes = noble_addr.to_wire_bytes();
        let wire_hex = hex::encode(&wire_bytes);
        let address_type = noble_addr.address_type().to_string();

        // Update in-memory gateway key to use this address.
        {
            let mut gw = self.gateway_key.write();
            *gw = Some(wire_bytes);
        }

        // Update in-memory reward address.
        {
            let mut ra = self.reward_address.write();
            *ra = Some(trimmed.clone());
        }

        // Persist to noble.toml via set_config_value if available.
        if let Some(ref set_fn) = self.set_config_value {
            let _ = set_fn("rewards", "reward_address", &trimmed);
        }

        tracing::info!(task = "rewards", "Reward address set: {address_type} → {wire_hex}");

        // Derive display address.
        let display_address = derive_display_address(&noble_addr, &trimmed);

        Ok(SetRewardAddressResponse {
            address_type,
            display_address,
            wire_hex,
        })
    }

    async fn get_reward_address(&self) -> Result<GetRewardAddressResponse, ErrorObjectOwned> {
        let ra = self.reward_address.read().clone();
        match ra {
            Some(addr) => {
                let noble_addr = parse_address(&addr).ok();
                let address_type = noble_addr.as_ref().map(|a| a.address_type().to_string());
                let wire_hex = noble_addr.map(|a| hex::encode(a.to_wire_bytes()));
                Ok(GetRewardAddressResponse {
                    configured: true,
                    address: Some(addr),
                    address_type,
                    wire_hex,
                })
            }
            None => Ok(GetRewardAddressResponse {
                configured: false,
                address: None,
                address_type: None,
                wire_hex: None,
            }),
        }
    }

    async fn set_config_value(
        &self,
        section: String,
        key: String,
        value: String,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned> {
        // Whitelist of allowed config keys.
        let allowed = [
            ("network", "listen_port"),
            ("api", "rpc_port"),
            ("api", "gui_port"),
        ];

        if !allowed.iter().any(|(s, k)| *s == section && *k == key) {
            return Err(ApiError::InvalidParam(format!(
                "config key '{section}.{key}' is not in the allowed whitelist"
            ))
            .into());
        }

        let set_fn = self.set_config_value.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("config update callback not configured".into())
        })?;

        let restart_required = set_fn(&section, &key, &value)
            .map_err(|e| ApiError::Internal(format!("update config: {e}")))?;

        tracing::info!(
            task = "config",
            "Config value {section}.{key} updated. Restart required: {restart_required}"
        );

        Ok(SetConfigValueResponse {
            success: true,
            restart_required,
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers for validator key management
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 validator key, write it to `path` (33 bytes: scheme_id + 32-byte secret),
/// set permissions to 0o600 on Unix, and return the hex-encoded wire pubkey.
fn generate_validator_key(path: &std::path::Path) -> Result<String, ErrorObjectOwned> {
    let (secret_bytes, _) = noble_crypto::ed25519::generate_keypair();
    let mut file_bytes = vec![SCHEME_ED25519];
    file_bytes.extend_from_slice(&secret_bytes);
    std::fs::write(path, &file_bytes)
        .map_err(|e| ApiError::Internal(format!("write validator.key: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    let private_key = noble_crypto::NoblePrivateKey::Ed25519(secret_bytes);
    Ok(hex::encode(private_key.public_key().to_wire_bytes()))
}

/// Calculate the total size of a directory recursively.
fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let ft = entry.file_type();
            if let Ok(ft) = ft {
                if ft.is_file() {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                } else if ft.is_dir() {
                    total += dir_size(&entry.path());
                }
            }
        }
    }
    total
}

/// Get the total capacity of the disk containing the given path.
fn disk_capacity(path: &std::path::Path) -> u64 {
    // Use sysinfo-like statvfs on unix, or a large default.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap_or_default();
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                return stat.f_blocks as u64 * stat.f_frsize as u64;
            }
        }
    }
    // Fallback: return 0 (GUI will show "N/A").
    #[cfg(not(unix))]
    { let _ = path; }
    0
}

/// Derive a display address for a NobleAddress.
fn derive_display_address(addr: &noble_core::NobleAddress, original: &str) -> String {
    match addr {
        noble_core::NobleAddress::BitcoinHash160(hash) => {
            // If original is a valid bitcoin address, return it as-is.
            if original.starts_with("bc1") || original.starts_with('1') || original.starts_with('3') {
                original.to_string()
            } else {
                // Derive bc1q... from hash160
                noble_crypto::bitcoin_addr::hash160_to_p2wpkh(hash, true)
            }
        }
        noble_core::NobleAddress::BitcoinTaproot(xonly) => {
            if original.starts_with("bc1p") {
                original.to_string()
            } else {
                noble_crypto::bitcoin_addr::xonly_to_p2tr(xonly, true)
            }
        }
        noble_core::NobleAddress::Noble(pk) => hex::encode(pk.to_wire_bytes()),
    }
}

/// Read an existing validator key file (33 bytes) and return the hex-encoded wire pubkey.
/// Returns `None` on any read or parse error.
fn read_validator_pubkey(path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    if raw.len() != 33 {
        return None;
    }
    let scheme_id = raw[0];
    let key_bytes = &raw[1..33];
    let private_key = match scheme_id {
        SCHEME_ED25519 => noble_crypto::NoblePrivateKey::Ed25519(key_bytes.to_vec()),
        SCHEME_SECP256K1 => noble_crypto::NoblePrivateKey::Secp256k1(key_bytes.to_vec()),
        _ => return None,
    };
    Some(hex::encode(private_key.public_key().to_wire_bytes()))
}
