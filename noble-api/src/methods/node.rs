// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node-related RPC methods: getNodeInfo, rotateTotpSecret, gateway info/rotation.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_consensus::ConsensusStateMachine;
use noble_core::{PROTOCOL_VERSION, SOFTWARE_VERSION};
use noble_storage::StorageEngine;

use crate::auth::TotpValidator;
use crate::error::ApiError;
use crate::state::{ApiState, NodeIdentityData};
use crate::types::*;

// Bring noble_crypto into scope for validator key generation.
use noble_crypto::SCHEME_SECP256K1;

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
        country_code: Option<String>,
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

    /// Get the current GUI admin-lock status (and whether TOTP is available so
    /// the Settings UI can gate the toggle).
    #[method(name = "getGuiLockStatus")]
    async fn get_gui_lock_status(&self) -> Result<GuiLockStatusResponse, ErrorObjectOwned>;

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
    /// Only a whitelist of keys is allowed.
    #[method(name = "setConfigValue")]
    async fn set_config_value(
        &self,
        section: String,
        key: String,
        value: String,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned>;

    /// Get the current rotating-log configuration (live size cap + whether file
    /// logging is active). Used by the GUI's Log Rotation settings panel.
    #[method(name = "getLoggingConfig")]
    async fn get_logging_config(&self) -> Result<LoggingConfigResponse, ErrorObjectOwned>;

    // ── Legacy faucet RPCs removed in open-node hardening PR ──
    // `getFaucetSecret` and `storeFaucetSecret` are deleted. The faucet binary
    // now reads chain_meta + passphrase + admin token directly from the node's
    // on-disk keystore (via `--node-data-dir`). The node eagerly creates both
    // secrets at startup so the faucet never has to write to the keystore over
    // RPC. Address propagation moved to a local-FS file (`faucet-address.txt`).

    /// Reset faucet rate limits by calling the faucet's HTTP API internally.
    #[method(name = "resetFaucetLimits")]
    async fn reset_faucet_limits(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the current faucet admin bearer token. Required by all faucet
    /// HTTP admin endpoints (e.g. `/api/faucet/reset-limits`). Operators see
    /// this in the GUI's Faucet settings panel; the faucet binary fetches it
    /// at boot and refreshes every 60 seconds.
    ///
    /// Auth-gated (NOT a `get*` read pattern — explicit carve-out in
    /// middleware.rs `is_read_method`).
    #[method(name = "getFaucetAdminToken")]
    async fn get_faucet_admin_token(&self) -> Result<FaucetAdminTokenResponse, ErrorObjectOwned>;

    /// Rotate the faucet admin bearer token. Generates new 32 random bytes,
    /// persists to keystore (scheme 0x86), returns the new token. The faucet
    /// binary picks up the change within 60 seconds via its refresh poller.
    #[method(name = "rotateFaucetAdminToken")]
    async fn rotate_faucet_admin_token(&self) -> Result<FaucetAdminTokenResponse, ErrorObjectOwned>;

    /// Detect the node's external (public) IP address by querying public services.
    ///
    /// Tries multiple IP-detection services in order; returns the first successful result.
    /// The returned `multiaddr` is pre-formatted for the node's P2P port.
    #[method(name = "detectExternalIp")]
    async fn detect_external_ip(&self) -> Result<DetectIpResponse, ErrorObjectOwned>;

    /// Check a data directory path for existence, writeability, and disk space.
    #[method(name = "checkDataDir")]
    async fn check_data_dir(
        &self,
        path: String,
    ) -> Result<CheckDataDirResponse, ErrorObjectOwned>;

    /// List directory contents for the folder browser.
    ///
    /// Returns directories and basic info for a given path.
    /// If path is empty, returns the filesystem root(s).
    #[method(name = "listDirectory")]
    async fn list_directory(
        &self,
        path: String,
    ) -> Result<ListDirectoryResponse, ErrorObjectOwned>;

    /// Get the current at-rest encryption status.
    ///
    /// Returns the encryption mode ("automatic" or "manual"), whether the
    /// `.chain_meta` file exists, and whether it is password-locked.
    #[method(name = "getEncryptionStatus")]
    async fn get_encryption_status(&self) -> Result<EncryptionStatusResponse, ErrorObjectOwned>;

    /// Switch the at-rest encryption mode.
    ///
    /// - `automatic → manual`: requires `new_password`
    /// - `manual → automatic`: requires `current_password`
    ///
    /// The in-memory encryption key does not change — only the on-disk format
    /// of `.chain_meta` is converted.  A node restart is recommended after switching.
    #[method(name = "setEncryptionMode")]
    async fn set_encryption_mode(
        &self,
        mode: String,
        current_password: Option<String>,
        new_password: Option<String>,
    ) -> Result<SetEncryptionModeResponse, ErrorObjectOwned>;

    /// Detect chain forks by grouping connected peers by their chain tip.
    ///
    /// Returns the local chain info and a list of detected forks, each with
    /// population count and KPIs for fork comparison.
    #[method(name = "getDetectedForks")]
    async fn get_detected_forks(&self) -> Result<DetectedForksResponse, ErrorObjectOwned>;

    /// Get blockchains discovered via NodeAnnounce from peers on different chains.
    ///
    /// Returns stored chain_id, network_name, and peer addresses for each
    /// discovered blockchain, useful for the Chain Management panel.
    #[method(name = "getDiscoveredBlockchains")]
    async fn get_discovered_blockchains(&self) -> Result<DiscoveredBlockchainsResponse, ErrorObjectOwned>;

    /// Get the current finality status of the chain.
    #[method(name = "getFinalityStatus")]
    async fn get_finality_status(&self) -> Result<FinalityStatusResponse, ErrorObjectOwned>;

    /// List all stored misbehavior evidence (double-proposal and vote equivocation).
    #[method(name = "getEvidenceList")]
    async fn get_evidence_list(&self) -> Result<EvidenceListResponse, ErrorObjectOwned>;

    /// Get a specific evidence record by hex-encoded hash.
    #[method(name = "getEvidence")]
    async fn get_evidence(&self, evidence_hash: String) -> Result<EvidenceDetailResponse, ErrorObjectOwned>;

    /// Get checkpoint status: interval, active checkpoints, highest reorg floor.
    #[method(name = "getCheckpoints")]
    async fn get_checkpoints(&self, limit: Option<usize>) -> Result<CheckpointsResponse, ErrorObjectOwned>;

    /// Get fork resolution status: strategy, dwell timer, safety floors.
    #[method(name = "getForkResolutionStatus")]
    async fn get_fork_resolution_status(&self) -> Result<ForkResolutionStatusResponse, ErrorObjectOwned>;

    /// Reset the chain to genesis and trigger re-sync from peers.
    ///
    /// This is a destructive operation used for fork recovery ("blockchain hop").
    /// Requires TOTP authentication (scope: All).
    #[method(name = "resetChain")]
    async fn reset_chain(&self) -> Result<ResetChainResponse, ErrorObjectOwned>;

    /// Create a tar.gz backup of the data directory.
    ///
    /// Writes to `{data_dir}/../noble-backup-{YYYYMMDD-HHMMSS}.tar.gz`.
    /// Returns the backup file path and size.
    /// Tarball the node's data directory to a sibling file. The default
    /// invocation EXCLUDES operator secret material (keystore, chain_meta,
    /// TLS key, validator key, TOTP secret). Pass `include_secrets: true`
    /// to produce a full archive — the boolean makes operator intent
    /// explicit in audit logs.
    ///
    /// TOTP-gated (open-node hardening): anonymous callers cannot trigger
    /// disk-fill DoS via unbounded tarball creation.
    #[method(name = "backupChain")]
    async fn backup_chain(
        &self,
        include_secrets: Option<bool>,
    ) -> Result<BackupChainResponse, ErrorObjectOwned>;
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

        // Chain identity: chain_id from config, genesis_hash from storage (empty if no chain).
        let chain_id = self.chain_id.load(std::sync::atomic::Ordering::Relaxed);
        let network_name = self.network_name.clone();
        let genesis_hash = self.genesis_hash.clone();

        let sync_behind = self.sync_behind.load(std::sync::atomic::Ordering::Relaxed);
        let sync_target_height = self.sync_target_height.load(std::sync::atomic::Ordering::Relaxed);
        let sync_current_height = self.sync_progress_current.load(std::sync::atomic::Ordering::Relaxed);
        let sync_progress_pct = if sync_behind && sync_target_height > 0 {
            (sync_current_height as f64 / sync_target_height as f64 * 100.0).min(100.0) as u64
        } else {
            0
        };

        Ok(NodeInfoResponse {
            version: SOFTWARE_VERSION.to_string(),
            software_version: SOFTWARE_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
            chain_id,
            network_name,
            genesis_hash,
            uptime_secs: uptime,
            rpc_port: self.rpc_port,
            ws_port: self.ws_port,
            p2p_port: self.p2p_port,
            peer_id: self.peer_id.clone(),
            latest_network_version,
            storage_bytes,
            storage_capacity_bytes,
            data_dir: data_dir_str,
            config_path: self.config_path.as_ref().map(|p| p.display().to_string()),
            validator_pubkey: self.validator_pubkey.read().clone(),
            validator_pubkey_display: self.validator_pubkey.read().as_ref().and_then(|hex_str| {
                let bytes = hex::decode(hex_str).ok()?;
                noble_crypto::noble_addr::encode_wire_bytes(&bytes)
            }),
            sync_behind,
            sync_target_height,
            sync_current_height,
            sync_progress_pct,
            faucet_address: {
                // In-memory value (set by legacy storeFaucetSecret) takes
                // precedence; falls back to <data_dir>/faucet-address.txt
                // written by the faucet binary in local-FS mode.
                let addr = self.faucet_address.read().clone();
                if !addr.is_empty() {
                    Some(addr)
                } else {
                    self.data_dir.as_ref().and_then(|d| {
                        let p = d.join("faucet-address.txt");
                        std::fs::read_to_string(&p)
                            .ok()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                    })
                }
            },
            faucet_enabled: self.faucet_enabled.load(std::sync::atomic::Ordering::Relaxed),
            faucet_listening: self.faucet_listening.load(std::sync::atomic::Ordering::Relaxed),
            faucet_listen: {
                let listen = self.faucet_listen.read().clone();
                if listen.is_empty() { None } else { Some(listen) }
            },
            min_fee_rate: self.min_fee_rate.load(std::sync::atomic::Ordering::Relaxed),
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
        // Ensure TOTP is enabled. Read the live slot (reflects a runtime enable
        // that the legacy `totp_validator` field does not); swapping its inner
        // Arc updates both the RPC AuthLayer and the GUI lock.
        let validator_arc = self
            .totp_slot
            .read()
            .clone()
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
        // Parse key: accept both nbl1… bech32 and hex wire bytes.
        let pk = if noble_crypto::noble_addr::is_noble_address(public_key.trim()) {
            noble_crypto::noble_addr::decode(public_key.trim())
                .map_err(|e| ApiError::InvalidAddress(e.to_string()))?
        } else {
            let new_key_bytes = ::hex::decode(&public_key)
                .map_err(|_| ApiError::InvalidAddress("invalid hex string".into()))?;
            noble_crypto::NoblePublicKey::from_wire_bytes(&new_key_bytes)
                .map_err(|e| ApiError::InvalidAddress(e.to_string()))?
        };
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
            *gw = Some(pk.to_wire_bytes());
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

        // Persist to noble.toml via set_config_value.
        if let Some(ref set_config) = self.set_config_value {
            let value = allowed_ips.join(",");
            if let Err(e) = set_config("api", "allowed_ips", &value) {
                tracing::warn!(task = "ip_filter", %e, "Failed to persist allowed_ips to noble.toml");
            }
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
            country_code: id.country_code.clone(),
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
        country_code: Option<String>,
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

        // Validate country_code if provided.
        let cc = country_code.unwrap_or_default();
        if !cc.is_empty()
            && (cc.len() != 3 || !cc.bytes().all(|b| b.is_ascii_uppercase()))
        {
            return Err(ApiError::InvalidParam(
                "country_code must be exactly 3 uppercase letters (ISO 3166-1 alpha-3)".into(),
            )
            .into());
        }

        let new_identity = NodeIdentityData {
            node_name,
            org_type,
            org_name: org_name.unwrap_or_default(),
            node_role,
            contact_email: contact_email.unwrap_or_default(),
            website: website.unwrap_or_default(),
            host_address: host_address.unwrap_or_default(),
            country_code: cc,
            wants_to_validate,
            wants_to_vote,
            p2p_port: port,
            setup_complete: true,
        };

        // Persist to identity.json atomically.
        if let Some(path) = &self.identity_path {
            // Ensure parent directory exists (may not exist on first setup).
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ApiError::Internal(format!("create data dir: {e}")))?;
                }
            }
            let json = serde_json::to_string_pretty(&new_identity)
                .map_err(|e| ApiError::Internal(format!("serialize identity: {e}")))?;
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, json.as_bytes())
                .map_err(|e| ApiError::Internal(format!("write identity tmp: {e}")))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| ApiError::Internal(format!("rename identity file: {e}")))?;
            tracing::info!(task = "identity", "Node identity persisted to {}", path.display());
        }

        // Capture values before move.
        let saved_node_name = new_identity.node_name.clone();

        // Update in-memory state.
        {
            let mut id = self.node_identity.write();
            *id = new_identity;
        }

        // Disable remote_setup now that setup is complete (security: prevent
        // re-exposure of the wizard if identity.json is later deleted).
        if let Some(ref set_fn) = self.set_config_value {
            if let Err(e) = set_fn("api", "remote_setup", "false") {
                tracing::warn!(task = "identity", "failed to disable remote_setup: {e}");
            }
        }

        // Trigger NodeAnnounce re-broadcast so peers see updated identity.
        if let Err(e) = self.announce_trigger.try_send(()) {
            tracing::debug!(task = "identity", "announce trigger send: {e}");
        }

        // Hot-reload engine flags so changes take effect without restart.
        // The setup wizard calls this RPC — without this, the engine would
        // keep the stale TOML defaults (e.g. voting_enabled=false) until
        // the next node restart.
        {
            let mut engine = self.consensus.write();
            engine.set_proposals_enabled(wants_to_validate);
            engine.set_voting_enabled(wants_to_vote);
            tracing::info!(
                task = "identity",
                "Engine flags hot-reloaded: proposals_enabled={wants_to_validate}, voting_enabled={wants_to_vote}",
            );
        }

        // A1: When the node is configured for validation, ensure a validator key exists.
        // secp256k1-everywhere: the validator key IS the wallet key. If a wallet key
        // exists in the keystore, copy it to validator.key. Otherwise fall back to
        // random generation (pre-wallet setup).
        let validator_pubkey = if wants_to_validate {
            if let Some(ref identity_path) = self.identity_path {
                if let Some(data_dir) = identity_path.parent() {
                    let vkey_path = data_dir.join("validator.key");
                    if vkey_path.exists() {
                        // Already exists — just read the pubkey.
                        read_validator_pubkey(&vkey_path, &self.chain_meta)
                    } else {
                        // validator.key should have been written by generateMnemonic/importMnemonic.
                        // If we reach here, the wallet was created without a validator key (bug or
                        // legacy flow). Log and skip — operator must re-run setup.
                        tracing::warn!(
                            task = "setup",
                            "No validator.key found. Generate or import a wallet to create one."
                        );
                        None
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

        // Hot-reload ApiState.validator_pubkey so resolve_node_name can match
        // self-votes immediately (without requiring a node restart).
        if let Some(ref pubkey_addr) = validator_pubkey {
            if let Ok(pk) = noble_crypto::noble_addr::decode(pubkey_addr) {
                let wire_hex = hex::encode(pk.to_wire_bytes());
                *self.validator_pubkey.write() = Some(wire_hex);
                *self.validator_scheme.write() = Some("secp256k1".to_string());
                if let Some(ref identity_path) = self.identity_path {
                    if let Some(data_dir) = identity_path.parent() {
                        *self.validator_key_path.write() = Some(
                            data_dir.join("validator.key").display().to_string()
                        );
                    }
                }
                tracing::info!(task = "setup", "Hot-reloaded validator_pubkey in ApiState");
            }
        }

        // Self-register in the validator registry so the node can propose/vote
        // immediately without requiring a restart.
        if wants_to_validate {
            if let Some(ref pubkey_addr) = validator_pubkey {
                // Decode the nbl1... address back to a NoblePublicKey for registry.
                if let Ok(pk) = noble_crypto::noble_addr::decode(pubkey_addr) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut reg = self.validator_registry.write();
                    if !reg.is_validator(&pk) {
                        reg.add_validator(pk.clone(), 1, now);
                        tracing::info!(
                            task = "setup",
                            "Self-registered as validator: {pubkey_addr}"
                        );
                    }
                    if !saved_node_name.is_empty() {
                        reg.set_friendly_name(&pk, saved_node_name.clone());
                    }
                }
            }
        }

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
        let vk = self.validator_pubkey.read().clone();
        let pubkey_display = vk.as_ref().and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            noble_crypto::noble_addr::encode_wire_bytes(&bytes)
        });
        Ok(ValidatorKeyInfoResponse {
            enabled: vk.is_some(),
            pubkey_hex: vk,
            pubkey_display,
            scheme: self.validator_scheme.read().clone(),
            key_path: self.validator_key_path.read().clone(),
        })
    }

    async fn enable_totp(&self) -> Result<EnableTotpResponse, ErrorObjectOwned> {
        // Reject if TOTP is already enabled (check the live slot, which reflects
        // a runtime enable that the legacy `totp_validator` field does not).
        if self.totp_slot.read().is_some() {
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
        // Read the live slot so a runtime enable/rotate is reflected immediately.
        let enabled = self.totp_slot.read().is_some();
        let scope = format!("{}", self.totp_scope);
        Ok(TotpStatusResponse { enabled, scope })
    }

    async fn get_gui_lock_status(&self) -> Result<GuiLockStatusResponse, ErrorObjectOwned> {
        Ok(GuiLockStatusResponse {
            enabled: self
                .gui_lock_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
            totp_available: self.totp_slot.read().is_some(),
        })
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

        // Update in-memory reward address (display).
        {
            let mut ra = self.reward_address.write();
            *ra = Some(trimmed.clone());
        }

        // Hot-reload into consensus engine — next block proposal uses the new address.
        {
            let mut era = self.engine_reward_address.write();
            *era = Some(noble_addr.clone());
        }

        // Persist to noble.toml via set_config_value if available.
        if let Some(ref set_fn) = self.set_config_value {
            if let Err(e) = set_fn("rewards", "reward_address", &trimmed) {
                tracing::warn!("failed to persist reward_address: {e}");
            }
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
            ("network", "listen_addr"),
            ("network", "max_peers"),
            ("network", "seeds"),
            ("api", "rpc_port"),
            ("api", "gui_port"),
            ("api", "allowed_ips"),
            ("api", "tls_san"),
            ("api", "gui_lock_enabled"),
            ("storage", "data_dir"),
            ("storage", "cache_size_mb"),
            ("storage", "compression"),
            ("storage", "pruning_mode"),
            ("storage", "keep_blocks"),
            ("security", "encryption_mode"),
            ("rewards", "reward_address"),
            ("consensus", "voting_strategy"),
            ("consensus", "confirmation_strategy"),
            ("consensus", "voting_preferred_validator"),
            ("consensus", "voting_subset"),
            ("faucet", "server_enabled"),
            ("faucet", "listen_addr"),
            ("faucet", "drip_amount"),
            ("faucet", "daily_cap"),
            ("faucet", "ip_cooldown_secs"),
            ("faucet", "address_cooldown_secs"),
            ("consensus", "min_fee_rate"),
            ("logging", "max_size_bytes"),
        ];

        if !allowed.iter().any(|(s, k)| *s == section && *k == key) {
            return Err(ApiError::InvalidParam(format!(
                "config key '{section}.{key}' is not in the allowed whitelist"
            ))
            .into());
        }

        // Validate the logging cap before persisting (don't write a footgun
        // value). Minimum 1 MiB; 0/disable is a config-file/restart decision,
        // not a live GUI action.
        const MIN_LOG_MAX_SIZE_BYTES: u64 = 1_048_576;
        if section == "logging" && key == "max_size_bytes" {
            match value.parse::<u64>() {
                Ok(v) if v >= MIN_LOG_MAX_SIZE_BYTES => {}
                Ok(v) => {
                    return Err(ApiError::InvalidParam(format!(
                        "logging.max_size_bytes must be >= {MIN_LOG_MAX_SIZE_BYTES} bytes (1 MiB); got {v}"
                    ))
                    .into());
                }
                Err(_) => {
                    return Err(ApiError::InvalidParam(format!(
                        "logging.max_size_bytes must be a positive integer; got '{value}'"
                    ))
                    .into());
                }
            }
        }

        // The GUI admin lock can only be enabled when TOTP is available — it is
        // the lock's authentication mechanism. Block the footgun of locking the
        // dashboard with no way to sign in.
        if section == "api" && key == "gui_lock_enabled" && value == "true" && self.totp_slot.read().is_none() {
            return Err(ApiError::InvalidParam(
                "enable TOTP before enabling the GUI admin lock".into(),
            )
            .into());
        }

        let set_fn = self.set_config_value.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("config update callback not configured".into())
        })?;

        let restart_required = set_fn(&section, &key, &value)
            .map_err(|e| ApiError::Internal(format!("update config: {e}")))?;

        // Hot-reload the GUI admin lock (the same Arc is shared into the GUI
        // server, so toggling takes effect on the next request — no restart).
        if section == "api" && key == "gui_lock_enabled" {
            self.gui_lock_enabled
                .store(value == "true", std::sync::atomic::Ordering::Relaxed);
        }

        // Update in-memory state for fields that support hot-reload.
        if section == "network" && key == "max_peers" {
            if let Ok(v) = value.parse::<u32>() {
                self.max_peers.store(v, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if section == "faucet" && key == "server_enabled" {
            self.faucet_enabled.store(value == "true", std::sync::atomic::Ordering::Relaxed);
        }
        if section == "consensus" && key == "min_fee_rate" {
            if let Ok(v) = value.parse::<u64>() {
                self.min_fee_rate.store(v, std::sync::atomic::Ordering::Relaxed);
                // Re-publish NodeAnnounce with updated min_fee_rate so peers see the change.
                if let Err(e) = self.announce_trigger.try_send(()) {
                    tracing::debug!(task = "config", "announce trigger after min_fee_rate change: {e}");
                }
            }
        }
        if section == "logging" && key == "max_size_bytes" {
            // Hot-reload the live cap (takes effect on the next rotation check)
            // when file logging is active. If it was disabled at startup, the
            // persisted value applies on restart.
            if let Ok(v) = value.parse::<u64>() {
                if let Some(ref th) = self.trace_handle {
                    th.set_log_max_size(v);
                    tracing::info!(task = "config", "Log max size hot-reloaded: {v} bytes");
                }
            }
        }
        if section == "rewards" && key == "reward_address" {
            // Hot-reload: update engine reward address + gateway key + display string.
            match parse_address(&value) {
                Ok(addr) => {
                    *self.engine_reward_address.write() = Some(addr.clone());
                    *self.gateway_key.write() = Some(addr.to_wire_bytes());
                    *self.reward_address.write() = Some(value.clone());
                    tracing::info!(task = "config", "Reward address hot-reloaded: {}", addr.address_type());
                }
                Err(e) => {
                    tracing::warn!(task = "config", "Invalid reward_address in hot-reload: {e}");
                }
            }
        }

        tracing::info!(
            task = "config",
            "Config value {section}.{key} updated. Restart required: {restart_required}"
        );

        Ok(SetConfigValueResponse {
            success: true,
            restart_required,
        })
    }

    async fn get_logging_config(&self) -> Result<LoggingConfigResponse, ErrorObjectOwned> {
        let max_size_bytes = self
            .trace_handle
            .as_ref()
            .map(|h| h.log_max_size())
            .unwrap_or(0);
        Ok(LoggingConfigResponse {
            max_size_bytes,
            file_enabled: max_size_bytes > 0,
        })
    }

    // ── Legacy faucet RPCs removed in open-node hardening ──
    // `get_faucet_secret` and `store_faucet_secret` deleted. Both were
    // operator-internal IPC channels that became dead code once the
    // faucet binary moved to local-FS bootstrap (`--node-data-dir`).
    // See node startup: `ensure_faucet_passphrase` + `ensure_faucet_admin_token`.
    // See faucet `main.rs`: writes address to `faucet-address.txt` instead.

    async fn reset_faucet_limits(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        /// Accepts any TLS cert — safe for localhost loopback only.
        #[derive(Debug)]
        struct NoCertVerify;
        impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
            fn verify_server_cert(&self, _: &rustls_pki_types::CertificateDer<'_>, _: &[rustls_pki_types::CertificateDer<'_>], _: &rustls_pki_types::ServerName<'_>, _: &[u8], _: rustls_pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
            }
        }
        let listen = self.faucet_listen.read().clone();
        if listen.is_empty() {
            return Err(ApiError::Internal("Faucet not configured".into()).into());
        }
        let port = listen.rsplit(':').next().unwrap_or("8786");
        let url = format!("https://127.0.0.1:{port}/api/faucet/reset-limits");

        // Forward the admin bearer token so the faucet's AdminAuthLayer
        // accepts the call. The node owns the token; we read it from our
        // keystore on every call (cheap, in-memory) and pass it on the
        // loopback request alongside the legacy Gatekeeper header.
        let (admin_token, _, _) = read_or_create_faucet_admin_token(self)
            .map_err(ErrorObjectOwned::from)?;

        let json = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
            let agent = ureq::AgentBuilder::new()
                .tls_config(std::sync::Arc::new(
                    rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerify))
                        .with_no_client_auth(),
                ))
                .build();
            let resp = agent.post(&url)
                .set("Gatekeeper", "noble")
                .set("Authorization", &format!("Bearer {admin_token}"))
                .call()
                .map_err(|e| format!("faucet request failed: {e}"))?;
            let body = resp
                .into_string()
                .map_err(|e| format!("faucet response: {e}"))?;
            serde_json::from_str(&body)
                .map_err(|e| format!("faucet json: {e}"))
        })
        .await
        .map_err(|e| ApiError::Internal(format!("task join: {e}")))?
        .map_err(|e| ApiError::Internal(e))?;

        Ok(json)
    }

    async fn get_faucet_admin_token(&self) -> Result<FaucetAdminTokenResponse, ErrorObjectOwned> {
        let (token, created_at_unix, fingerprint) =
            read_or_create_faucet_admin_token(self).map_err(ErrorObjectOwned::from)?;
        Ok(FaucetAdminTokenResponse { token, created_at_unix, fingerprint })
    }

    async fn rotate_faucet_admin_token(&self) -> Result<FaucetAdminTokenResponse, ErrorObjectOwned> {
        let (token, created_at_unix, fingerprint) =
            rotate_faucet_admin_token_inner(self).map_err(ErrorObjectOwned::from)?;
        tracing::info!(
            task = "faucet_admin",
            fingerprint = %fingerprint,
            "faucet admin token rotated"
        );
        Ok(FaucetAdminTokenResponse { token, created_at_unix, fingerprint })
    }

    async fn detect_external_ip(&self) -> Result<DetectIpResponse, ErrorObjectOwned> {
        let p2p_port = self.p2p_port;
        tokio::task::spawn_blocking(move || {
            // All 4 services return text/plain on their /ip endpoints.
            // icanhazip.com appends a trailing \n; the rest return bare IP.
            // All ignore Accept headers on these paths. We set explicit headers
            // for robustness and to avoid being served HTML error pages.
            let services = [
                "https://ipinfo.io/ip",
                "https://icanhazip.com",
                "https://ifconfig.me/ip",
                "https://api.ipify.org",
            ];
            let mut last_error = String::new();
            for url in &services {
                match ureq::get(url)
                    .set("Accept", "text/plain")
                    .set("User-Agent", "noble-node/0.8")
                    .timeout(std::time::Duration::from_secs(5))
                    .call()
                {
                    Ok(resp) => {
                        if let Ok(body) = resp.into_string() {
                            let ip = body.trim().to_string();
                            // Validate: must parse as a real IP address.
                            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                                let multiaddr = match addr {
                                    std::net::IpAddr::V4(_) => format!("/ip4/{ip}/tcp/{p2p_port}"),
                                    std::net::IpAddr::V6(_) => format!("/ip6/{ip}/tcp/{p2p_port}"),
                                };
                                return Ok(DetectIpResponse {
                                    ip,
                                    multiaddr,
                                    source: url.to_string(),
                                });
                            }
                            last_error = format!("{url}: response is not a valid IP: {ip}");
                        }
                    }
                    Err(e) => {
                        last_error = format!("{url}: {e}");
                    }
                }
            }
            Err(ApiError::Internal(format!(
                "Could not detect external IP. Last error: {last_error}"
            ))
            .into())
        })
        .await
        .map_err(|e| ApiError::Internal(format!("spawn_blocking: {e}")))?
    }

    async fn check_data_dir(
        &self,
        path: String,
    ) -> Result<CheckDataDirResponse, ErrorObjectOwned> {
        // When path is empty, use the node's configured data_dir as default.
        let effective_path: std::path::PathBuf = if path.trim().is_empty() {
            self.data_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        } else {
            std::path::PathBuf::from(&path)
        };
        let p = effective_path.as_path();

        let exists = p.exists();
        let mut writable = false;
        let available_bytes: u64;
        let mut error: Option<String> = None;

        // Writability check by metadata (no `.noble_write_test` files left
        // littering the filesystem). On Unix, walking up the path until we
        // find an existing ancestor gives us the right answer for both
        // "exists" and "would be created here" cases. This method is
        // TOTP-gated (audit follow-up #1), so it's only called by operators.
        if exists {
            writable = path_appears_writable(p);
            if !writable {
                error = Some("path metadata indicates not writable".into());
            }
        } else {
            // Walk up to the first existing ancestor and check its writability.
            let mut probe = p.parent();
            while let Some(parent) = probe {
                if parent.exists() {
                    writable = path_appears_writable(parent);
                    if !writable {
                        error = Some(format!(
                            "ancestor {} appears not writable",
                            parent.display()
                        ));
                    }
                    break;
                }
                probe = parent.parent();
            }
        }

        // Get disk space via sysinfo
        let check_path = if exists { p } else { p.parent().unwrap_or(p) };
        available_bytes = disk_available(check_path);

        Ok(CheckDataDirResponse {
            exists,
            writable,
            available_bytes,
            error,
        })
    }

    async fn list_directory(
        &self,
        path: String,
    ) -> Result<ListDirectoryResponse, ErrorObjectOwned> {
        let effective: String = if path.trim().is_empty() { "/".to_string() } else { path };
        let p = std::path::PathBuf::from(&effective);

        if !p.exists() {
            return Ok(ListDirectoryResponse {
                current: effective,
                parent: p.parent().map(|pp| pp.display().to_string()).unwrap_or_default(),
                entries: vec![],
                error: Some("Path does not exist".into()),
            });
        }
        if !p.is_dir() {
            return Ok(ListDirectoryResponse {
                current: effective,
                parent: p.parent().map(|pp| pp.display().to_string()).unwrap_or_default(),
                entries: vec![],
                error: Some("Path is not a directory".into()),
            });
        }

        let parent = p.parent().map(|pp| pp.display().to_string()).unwrap_or_default();
        let mut entries = Vec::new();

        match std::fs::read_dir(p) {
            Ok(rd) => {
                for entry in rd.flatten() {
                    let ft = entry.file_type();
                    let is_dir = ft.as_ref().map(|f| f.is_dir()).unwrap_or(false);
                    if !is_dir { continue; } // Only show directories.
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') { continue; } // Skip hidden dirs.
                    let full_path = entry.path().display().to_string();
                    // Writability via metadata check — no `.noble_write_test`
                    // files left across the host filesystem. This method is
                    // TOTP-gated; called only by operators.
                    let writable = path_appears_writable(&entry.path());
                    entries.push(DirectoryEntry { name, path: full_path, is_dir, writable });
                }
                entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            }
            Err(e) => {
                return Ok(ListDirectoryResponse {
                    current: effective,
                    parent,
                    entries: vec![],
                    error: Some(format!("Cannot read directory: {e}")),
                });
            }
        }

        Ok(ListDirectoryResponse {
            current: effective,
            parent,
            entries,
            error: None,
        })
    }

    async fn get_encryption_status(&self) -> Result<EncryptionStatusResponse, ErrorObjectOwned> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("data_dir not configured".into())
        })?;

        let (exists, is_locked) = noble_crypto::file_encrypt::chain_meta_status(data_dir);
        let mode = if is_locked { "manual" } else { "automatic" }.to_string();

        Ok(EncryptionStatusResponse {
            mode,
            chain_meta_exists: exists,
            is_locked,
        })
    }

    async fn set_encryption_mode(
        &self,
        mode: String,
        current_password: Option<String>,
        new_password: Option<String>,
    ) -> Result<SetEncryptionModeResponse, ErrorObjectOwned> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("data_dir not configured".into())
        })?;

        if mode != "automatic" && mode != "manual" {
            return Err(ApiError::InvalidParam(format!(
                "invalid mode '{mode}': expected 'automatic' or 'manual'"
            ))
            .into());
        }

        noble_crypto::file_encrypt::switch_encryption_mode(
            data_dir,
            &self.chain_meta,
            &mode,
            current_password.as_deref(),
            new_password.as_deref(),
        )
        .map_err(|e| ApiError::Internal(format!("switch encryption mode: {e}")))?;

        // Persist mode to noble.toml
        if let Some(ref set_fn) = self.set_config_value {
            if let Err(e) = set_fn("security", "encryption_mode", &mode) {
                tracing::warn!("failed to persist encryption_mode: {e}");
            }
        }

        let message = format!("Encryption mode switched to '{mode}'. Restart recommended.");
        tracing::info!(task = "encryption", "{message}");

        Ok(SetEncryptionModeResponse {
            success: true,
            restart_required: true,
            message,
        })
    }

    async fn get_detected_forks(&self) -> Result<DetectedForksResponse, ErrorObjectOwned> {
        let (local_height, local_tip_bytes) = {
            let consensus = self.consensus.read();
            consensus.chain_tip()
        };
        let local_tip = hex::encode(local_tip_bytes);

        // Aggregate peer chain tips by tip_hash.
        // Only include same-chain peers (chain_id match or unknown) to avoid
        // cross-chain peers appearing as "diverged" forks.
        let local_chain_id = self.chain_id.load(std::sync::atomic::Ordering::Relaxed);
        let peer_tips: Vec<(String, u64, String)> = {
            let info = self.peer_info.read();
            info.values()
                .filter_map(|entry| {
                    // Skip peers on a different chain.
                    if let Some(cid) = entry.chain_id {
                        if local_chain_id != 0 && cid != local_chain_id {
                            return None;
                        }
                    }
                    let h = entry.chain_tip_height?;
                    let hash = entry.chain_tip_hash.clone()?;
                    Some((entry.peer_id.clone(), h, hash))
                })
                .collect()
        };
        let peer_count = peer_tips.len();

        // Group by tip_hash.
        let mut groups: std::collections::HashMap<String, (u64, usize)> =
            std::collections::HashMap::new();
        for (_peer_id, height, tip_hash) in &peer_tips {
            let entry = groups.entry(tip_hash.clone()).or_insert((*height, 0));
            entry.1 += 1;
            // Use the max height among peers reporting this tip.
            if *height > entry.0 {
                entry.0 = *height;
            }
        }

        // Always include local chain as a fork entry.
        let local_entry = groups.entry(local_tip.clone()).or_insert((local_height, 0));
        // Ensure height reflects local tip.
        if local_height > local_entry.0 {
            local_entry.0 = local_height;
        }

        // Highest known height across all peers.
        let highest_known = peer_tips.iter().map(|(_, h, _)| *h).max().unwrap_or(local_height).max(local_height);

        // For each non-local fork, check if its tip agrees with our local chain
        // at that height.  This distinguishes "behind on same chain" from "diverged".
        let storage = self.storage.read();
        let mut forks: Vec<ForkEntry> = groups
            .into_iter()
            .map(|(tip_hash, (height, peers))| {
                let is_local = tip_hash == local_tip;
                let agrees_with_local = if is_local {
                    Some(true)
                } else if height > local_height {
                    // Peer is ahead — we can't verify (we don't have their block).
                    None
                } else {
                    // Peer is at or below our height — check if their tip matches
                    // our block at their height.
                    match noble_crypto::Hash256::from_hex(&tip_hash) {
                        Ok(peer_hash) => {
                            match storage.get_block_hash_by_height(height) {
                                Ok(our_hash) => Some(our_hash == peer_hash),
                                // Storage error at or below our height: can't
                                // confirm agreement → treat as diverged.
                                Err(_) => Some(false),
                            }
                        }
                        Err(_) => Some(false),
                    }
                };
                ForkEntry {
                    is_local,
                    tip_hash,
                    height,
                    peers,
                    agrees_with_local,
                }
            })
            .collect();

        // Sort by height descending (tallest fork first).
        forks.sort_by(|a, b| b.height.cmp(&a.height));

        Ok(DetectedForksResponse {
            local_height,
            local_tip,
            peer_count,
            highest_known,
            forks,
        })
    }

    async fn get_discovered_blockchains(&self) -> Result<DiscoveredBlockchainsResponse, ErrorObjectOwned> {
        let discovered = self.discovered_blockchains.lock();
        let mut blockchains: Vec<DiscoveredBlockchainEntry> = discovered
            .values()
            .map(|info| DiscoveredBlockchainEntry {
                chain_id: format!("{:#010X}", info.chain_id),
                network_name: info.network_name.clone(),
                peer_addresses: info.peer_addresses.clone(),
                first_seen: info.first_seen,
                last_seen: info.last_seen,
            })
            .collect();
        // Sort by most recently seen first.
        blockchains.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        Ok(DiscoveredBlockchainsResponse { blockchains })
    }

    async fn get_finality_status(&self) -> Result<FinalityStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let ft = consensus.finality_tracker();
        let (tip_height, tip_hash) = consensus.chain_tip();
        let confirmations = ft.confirmations_for_tip();
        let status = ft.status_for_height(tip_height);
        Ok(FinalityStatusResponse {
            finalized_height: ft.finalized_height,
            finalized_hash: hex::encode(ft.finalized_hash.as_bytes()),
            finalized_at_cycle: ft.finalized_at_cycle,
            confirmation_threshold: ft.confirmation_threshold(),
            latest_height: tip_height,
            latest_hash: hex::encode(tip_hash.as_bytes()),
            confirmations_for_latest: confirmations,
            status: match status {
                noble_consensus::FinalityStatus::Committed => "committed",
                noble_consensus::FinalityStatus::Confirmed { .. } => "confirmed",
                noble_consensus::FinalityStatus::Finalized => "finalized",
            }
            .to_string(),
        })
    }

    async fn get_evidence_list(&self) -> Result<EvidenceListResponse, ErrorObjectOwned> {
        let entries = self
            .storage
            .read()
            .list_evidence()
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        let mut evidence = Vec::with_capacity(entries.len());
        for (hash, cbor) in &entries {
            let (evidence_type, validator) =
                decode_evidence_summary(cbor).unwrap_or(("unknown".into(), String::new()));
            evidence.push(EvidenceEntry {
                evidence_hash: hex::encode(hash),
                evidence_type,
                validator,
            });
        }
        let total = evidence.len();
        Ok(EvidenceListResponse { evidence, total })
    }

    async fn get_evidence(&self, evidence_hash: String) -> Result<EvidenceDetailResponse, ErrorObjectOwned> {
        let hash_bytes = hex::decode(&evidence_hash)
            .map_err(|_| ApiError::InvalidParam("invalid hex hash".into()))?;

        let cbor = self
            .storage
            .read()
            .get_evidence(&hash_bytes)
            .map_err(|e| ApiError::Storage(e.to_string()))?
            .ok_or_else(|| ApiError::Storage("evidence not found".into()))?;

        let (evidence_type, validator, detail) =
            decode_evidence_detail(&cbor).unwrap_or(("unknown".into(), String::new(), serde_json::json!({})));

        Ok(EvidenceDetailResponse {
            evidence_hash,
            evidence_type,
            validator,
            detail,
        })
    }

    async fn get_checkpoints(&self, limit: Option<usize>) -> Result<CheckpointsResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let mgr = consensus.checkpoint_manager();
        let limit = limit.unwrap_or(20);
        let recent = mgr.recent_checkpoints(limit);
        let checkpoints: Vec<CheckpointEntry> = recent
            .iter()
            .map(|cp| CheckpointEntry {
                height: cp.height,
                hash: hex::encode(cp.hash.as_bytes()),
                created_at_cycle: cp.created_at_cycle,
                activates_at_cycle: cp.activates_at_cycle,
                active: cp.active,
            })
            .collect();
        Ok(CheckpointsResponse {
            checkpoint_interval: mgr.interval(),
            total_checkpoints: mgr.total(),
            highest_active_height: mgr.highest_active_height(),
            checkpoints,
        })
    }

    async fn get_fork_resolution_status(&self) -> Result<ForkResolutionStatusResponse, ErrorObjectOwned> {
        let resolver = self.fork_resolver.lock();
        let strategy = match resolver.strategy() {
            noble_consensus::ForkResolutionStrategy::Manual => "manual",
            noble_consensus::ForkResolutionStrategy::PeerSupermajority => "peer_supermajority",
            noble_consensus::ForkResolutionStrategy::LongestMostLegitimate => "longest_most_legitimate",
        };
        let dwell_counter = resolver.dwell_counter();
        let delay_cycles = resolver.min_fork_duration();
        let tracking_fork = resolver.tracked_fork_height().map(|h| format!("height:{h}"));
        drop(resolver);
        let consensus = self.consensus.read();
        let finalized_floor = consensus.finality_tracker().finalized_height;
        let checkpoint_floor = consensus.checkpoint_manager().highest_active_height();
        Ok(ForkResolutionStatusResponse {
            strategy: strategy.to_string(),
            delay_cycles,
            dwell_counter,
            tracking_fork,
            finalized_floor,
            checkpoint_floor,
        })
    }

    async fn reset_chain(&self) -> Result<ResetChainResponse, ErrorObjectOwned> {
        // TOTP auth required (scope: All). Check via request extensions.
        // The TOTP middleware handles this at the RPC layer.

        let previous_height = {
            let consensus = self.consensus.read();
            consensus.chain_tip().0
        };

        if previous_height == 0 {
            return Ok(ResetChainResponse {
                reset: true,
                previous_height: 0,
            });
        }

        // Reset storage to genesis.
        {
            let storage = self.storage.read();
            storage
                .force_reset_to_genesis(self.chain_id.load(std::sync::atomic::Ordering::Relaxed))
                .map_err(|e| ApiError::Internal(format!("reset chain: {e}")))?;
            // Clear stale cycle history from the old chain — the new chain
            // will produce its own history starting from block 1.
            if let Err(e) = storage.clear_cycle_history() {
                tracing::warn!(task = "chain_reset", "failed to clear cycle history: {e}");
            }
        }

        // Reset consensus engine — enters pre-genesis mode (cycles = 0 until
        // new chain's block 1 sets the epoch).
        {
            let storage = self.storage.read();
            let tip = storage
                .get_chain_tip()
                .map_err(|e| ApiError::Internal(format!("read tip after reset: {e}")))?
                .unwrap_or(noble_storage::ChainTip {
                    block_hash: noble_crypto::Hash256::ZERO,
                    height: 0,
                });
            let mut engine = self.consensus.write();
            engine.reset_tip(tip.height, tip.block_hash, true)
                .map_err(|e| ApiError::Internal(format!("reset_tip: {e}")))?;
        }

        // Trigger re-sync from peers.
        let _ = self.network_cmd.try_send(noble_network::NetworkCommand::RequestSync);

        tracing::warn!(
            task = "chain_reset",
            "Chain reset to genesis (previous height: {previous_height})"
        );

        Ok(ResetChainResponse {
            reset: true,
            previous_height,
        })
    }

    async fn backup_chain(
        &self,
        include_secrets: Option<bool>,
    ) -> Result<BackupChainResponse, ErrorObjectOwned> {
        let data_dir = self.data_dir.as_ref().ok_or_else(|| {
            ApiError::InvalidParam("data_dir not configured".into())
        })?;

        if !data_dir.exists() {
            return Err(ApiError::InvalidParam("data directory does not exist".into()).into());
        }

        let include_secrets = include_secrets.unwrap_or(false);

        // Build backup filename: noble-backup-YYYYMMDD-HHMMSS.tar.gz
        let now = chrono_timestamp();
        let parent = data_dir.parent().unwrap_or(data_dir);
        let backup_path = parent.join(format!("noble-backup-{now}.tar.gz"));
        let data_dir_clone = data_dir.clone();
        let backup_clone = backup_path.clone();

        // Operator-secret files relative to the tar -C root (the data_dir's
        // parent), so they need the data_dir's leaf name as the prefix.
        let dir_name = data_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let secret_excludes: Vec<String> = if include_secrets {
            tracing::warn!(
                task = "backup",
                "backupChain called with include_secrets=true — tarball will contain operator secrets"
            );
            Vec::new()
        } else {
            vec![
                format!("{dir_name}/keystore.noble"),
                format!("{dir_name}/.chain_meta"),
                format!("{dir_name}/tls-key.pem"),
                format!("{dir_name}/validator.key"),
                format!("{dir_name}/totp-secret.txt"),
                format!("{dir_name}/totp.secret"),
            ]
        };

        // Run tar in a blocking task to avoid blocking the async runtime.
        let result = tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("tar");
            for excl in &secret_excludes {
                cmd.arg("--exclude").arg(excl);
            }
            cmd.arg("czf")
                .arg(&backup_clone)
                .arg("-C")
                .arg(data_dir_clone.parent().unwrap_or(&data_dir_clone))
                .arg(
                    data_dir_clone
                        .file_name()
                        .unwrap_or_default(),
                )
                .output()
        })
        .await
        .map_err(|e| ApiError::Internal(format!("spawn tar: {e}")))?
        .map_err(|e| ApiError::Internal(format!("tar command: {e}")))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(ApiError::Internal(format!("tar failed: {stderr}")).into());
        }

        let size_bytes = std::fs::metadata(&backup_path)
            .map(|m| m.len())
            .unwrap_or(0);

        tracing::info!(
            task = "backup",
            "Chain backup created: {} ({} bytes)",
            backup_path.display(),
            size_bytes
        );

        Ok(BackupChainResponse {
            path: backup_path.display().to_string(),
            size_bytes,
        })
    }
}

/// Generate a compact timestamp string for backup filenames.
fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple: YYYYMMDD-HHMMSS from unix timestamp
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    // Approximate date (good enough for filenames)
    let (year, month, day) = unix_days_to_ymd(days);
    format!("{year:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}")
}

fn unix_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Civil calendar conversion (good for 2000-2099)
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Private helpers for validator key management
// ---------------------------------------------------------------------------

/// Calculate the total size of a directory recursively.
pub(crate) fn dir_size(path: &std::path::Path) -> u64 {
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
pub(crate) fn disk_capacity(path: &std::path::Path) -> u64 {
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

/// Best-effort "is this path writable by the current process?" check that
/// does NOT write anything to disk. Avoids the `.noble_write_test` litter
/// pattern of the prior implementation. On Unix, uses `access(2)` via
/// `libc::access`. On other platforms, falls back to metadata read-only
/// check (returns true if the path exists and isn't readonly).
///
/// Used by the TOTP-gated `checkDataDir` + `listDirectory` operator tools.
pub(crate) fn path_appears_writable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // W_OK = 2 — check write permission for the calling process.
        unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        match std::fs::metadata(path) {
            Ok(md) => !md.permissions().readonly(),
            Err(_) => false,
        }
    }
}

/// Get the available (free) disk space at the given path.
pub(crate) fn disk_available(path: &std::path::Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap_or_default();
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                return stat.f_bavail as u64 * stat.f_frsize as u64;
            }
        }
    }
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
        noble_core::NobleAddress::Noble(pk) => pk.to_address(),
    }
}

/// Read an existing validator key file and return the hex-encoded wire pubkey.
/// Handles both Noble-envelope encrypted and legacy plaintext (33-byte) formats.
/// Returns `None` on any read or parse error.
fn read_validator_pubkey(path: &std::path::Path, chain_meta: &[u8; 32]) -> Option<String> {
    let file_bytes = std::fs::read(path).ok()?;
    let raw = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
        let (d, _migrated) = noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, chain_meta).ok()?;
        d
    } else {
        file_bytes
    };
    if raw.len() != 33 {
        return None;
    }
    let scheme_id = raw[0];
    let key_bytes = &raw[1..33];
    let private_key = match scheme_id {
        SCHEME_SECP256K1 => noble_crypto::NoblePrivateKey::Secp256k1(key_bytes.to_vec()),
        _ => return None,
    };
    Some(private_key.public_key().to_address())
}

/// Decode CBOR evidence into (type, validator_hex) for list display.
fn decode_evidence_summary(cbor: &[u8]) -> Option<(String, String)> {
    use noble_codec::NobleCbor;
    let evidence = noble_core::MisbehaviorEvidence::from_cbor(cbor).ok()?;
    let (ty, validator) = match &evidence {
        noble_core::MisbehaviorEvidence::DoubleProposal(e) => {
            ("double_proposal".to_string(), e.validator_id.to_address())
        }
        noble_core::MisbehaviorEvidence::VoteEquivocation(e) => {
            ("vote_equivocation".to_string(), e.voter_pubkey.to_address())
        }
        noble_core::MisbehaviorEvidence::InvalidBlock(e) => {
            ("invalid_block".to_string(), e.block.header.validator_id.to_address())
        }
        noble_core::MisbehaviorEvidence::AnnounceEquivocation(e) => {
            ("announce_equivocation".to_string(), e.identity_key.to_address())
        }
    };
    Some((ty, validator))
}

/// Decode CBOR evidence into (type, validator_hex, detail_json) for single-record display.
fn decode_evidence_detail(cbor: &[u8]) -> Option<(String, String, serde_json::Value)> {
    use noble_codec::NobleCbor;
    let evidence = noble_core::MisbehaviorEvidence::from_cbor(cbor).ok()?;
    let (ty, validator, detail) = match &evidence {
        noble_core::MisbehaviorEvidence::DoubleProposal(e) => {
            let detail = serde_json::json!({
                "header_a_height": e.header_a.height,
                "header_b_height": e.header_b.height,
                "header_a_hash": e.header_a.compute_block_hash()
                    .map(|h| hex::encode(h.as_bytes())).unwrap_or_default(),
                "header_b_hash": e.header_b.compute_block_hash()
                    .map(|h| hex::encode(h.as_bytes())).unwrap_or_default(),
            });
            ("double_proposal".to_string(), e.validator_id.to_address(), detail)
        }
        noble_core::MisbehaviorEvidence::VoteEquivocation(e) => {
            let detail = serde_json::json!({
                "cycle": e.cycle,
                "round": e.round,
                "candidate_a": hex::encode(e.candidate_a.as_bytes()),
                "candidate_b": hex::encode(e.candidate_b.as_bytes()),
            });
            ("vote_equivocation".to_string(), e.voter_pubkey.to_address(), detail)
        }
        noble_core::MisbehaviorEvidence::InvalidBlock(e) => {
            let detail = serde_json::json!({
                "block_height": e.block.header.height,
                "block_hash": e.block.header.compute_block_hash()
                    .map(|h| hex::encode(h.as_bytes())).unwrap_or_default(),
                "failure_code": format!("{:?}", e.failure_code),
            });
            ("invalid_block".to_string(), e.block.header.validator_id.to_address(), detail)
        }
        noble_core::MisbehaviorEvidence::AnnounceEquivocation(e) => {
            let detail = serde_json::json!({
                "contradiction": format!("{:?}", e.contradiction),
                "announce_a_timestamp": e.announce_a.timestamp,
                "announce_b_timestamp": e.announce_b.timestamp,
            });
            ("announce_equivocation".to_string(), e.identity_key.to_address(), detail)
        }
    };
    Some((ty, validator, detail))
}

// ── Faucet admin token helpers ────────────────────────────────────────────
//
// Storage format in keystore scheme 0x86 (`SCHEME_FAUCET_ADMIN_TOKEN`):
//   [0..8]   little-endian u64, creation/rotation timestamp (UNIX seconds)
//   [8..40]  32 raw random bytes, hex-encoded only when returned via RPC
//
// `read_or_create` lazily bootstraps the token on first call (matches the
// faucet passphrase pattern). `rotate` always generates a new value and
// replaces the previous one atomically. Fingerprint is the first 8 hex
// chars of SHA-256(token_hex) — for log correlation without leaking the token.

fn faucet_admin_token_fingerprint(token_hex: &str) -> String {
    let digest = noble_crypto::sha256(token_hex.as_bytes());
    hex::encode(&digest.as_bytes()[..4])
}

/// Get-or-create the faucet admin token in the supplied keystore.
/// Parameter-shaped helper (not generic over `ApiState<S>`) so callers
/// without RPC state — e.g. node startup — can use it. Returns
/// `(token_hex, created_at_unix, fingerprint)`.
///
/// Audit follow-up #4: this function is now callable from node startup
/// (via [`ensure_faucet_admin_token`]) so the token is present in the
/// keystore before the faucet subprocess starts reading via local-FS.
pub fn read_or_create_faucet_admin_token_with(
    keystore: &parking_lot::Mutex<noble_wallet::KeyStore>,
    chain_meta: &[u8; 32],
) -> Result<(String, u64, String), String> {
    let wallet_pass = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(chain_meta));
    let mut ks = keystore.lock();
    if !ks.is_unlocked() {
        ks.unlock(&wallet_pass)
            .map_err(|e| format!("unlock keystore: {e}"))?;
    }
    if let Ok(bytes) = ks.get_raw(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN) {
        if bytes.len() == 40 {
            let ts_bytes: [u8; 8] = bytes[..8].try_into().unwrap_or([0u8; 8]);
            let timestamp = u64::from_le_bytes(ts_bytes);
            let token_hex = hex::encode(&bytes[8..]);
            let fp = faucet_admin_token_fingerprint(&token_hex);
            return Ok((token_hex, timestamp, fp));
        }
        // Corrupt entry — fall through to regenerate.
        tracing::warn!(
            task = "faucet_admin",
            "stored admin token has unexpected length ({} bytes) — regenerating",
            bytes.len()
        );
    }

    // Generate new token (lazy bootstrap on first call after node install,
    // or eager via ensure_faucet_admin_token at node startup).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut token_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
    let mut stored = Vec::with_capacity(40);
    stored.extend_from_slice(&now.to_le_bytes());
    stored.extend_from_slice(&token_bytes);

    if ks
        .has_scheme(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN)
        .unwrap_or(false)
    {
        let _ = ks.delete_by_scheme(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN);
    }
    ks.store_raw(
        noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN,
        &stored,
        &wallet_pass,
    )
    .map_err(|e| format!("store admin token: {e}"))?;

    let token_hex = hex::encode(token_bytes);
    let fp = faucet_admin_token_fingerprint(&token_hex);
    tracing::info!(
        task = "faucet_admin",
        fingerprint = %fp,
        "faucet admin token bootstrapped"
    );
    Ok((token_hex, now, fp))
}

/// Always-rotate variant of [`read_or_create_faucet_admin_token_with`].
/// Generates a fresh token even if one already exists; persists
/// atomically (delete + store). Returns the new value.
pub fn rotate_faucet_admin_token_with(
    keystore: &parking_lot::Mutex<noble_wallet::KeyStore>,
    chain_meta: &[u8; 32],
) -> Result<(String, u64, String), String> {
    let wallet_pass = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(chain_meta));
    let mut ks = keystore.lock();
    if !ks.is_unlocked() {
        ks.unlock(&wallet_pass)
            .map_err(|e| format!("unlock keystore: {e}"))?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut token_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
    let mut stored = Vec::with_capacity(40);
    stored.extend_from_slice(&now.to_le_bytes());
    stored.extend_from_slice(&token_bytes);

    if ks
        .has_scheme(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN)
        .unwrap_or(false)
    {
        let _ = ks.delete_by_scheme(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN);
    }
    ks.store_raw(
        noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN,
        &stored,
        &wallet_pass,
    )
    .map_err(|e| format!("store admin token: {e}"))?;

    let token_hex = hex::encode(token_bytes);
    let fp = faucet_admin_token_fingerprint(&token_hex);
    Ok((token_hex, now, fp))
}

/// Idempotent "ensure the admin token exists in the keystore." Returns
/// the current token's fingerprint (creating one if absent). Designed to
/// be called from node startup so the faucet subprocess finds the token
/// already present on local-FS bootstrap — eliminates the "admin endpoint
/// returns 503 until the operator clicks the GUI" failure mode.
///
/// Audit follow-up #4.
pub fn ensure_faucet_admin_token(
    keystore: &parking_lot::Mutex<noble_wallet::KeyStore>,
    chain_meta: &[u8; 32],
) -> Result<String, String> {
    read_or_create_faucet_admin_token_with(keystore, chain_meta)
        .map(|(_token, _ts, fp)| fp)
}

/// Idempotent "ensure the faucet passphrase exists in the keystore."
/// Symmetric to [`ensure_faucet_admin_token`]: if the keystore already
/// has `SCHEME_FAUCET_PASSPHRASE` populated, leaves it alone; otherwise
/// generates 32 random bytes (hex-encoded → 64 chars) and stores them.
/// Designed for node startup, so the faucet subprocess on local-FS
/// bootstrap finds the passphrase pre-existing and never calls the
/// legacy `storeFaucetSecret` RPC.
///
/// Open-node hardening Group 4 (audit follow-up #4 + #5).
pub fn ensure_faucet_passphrase(
    keystore: &parking_lot::Mutex<noble_wallet::KeyStore>,
    chain_meta: &[u8; 32],
) -> Result<(), String> {
    let wallet_pass = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(chain_meta));
    let mut ks = keystore.lock();
    if !ks.is_unlocked() {
        ks.unlock(&wallet_pass)
            .map_err(|e| format!("unlock keystore: {e}"))?;
    }
    if ks
        .has_scheme(noble_crypto::SCHEME_FAUCET_PASSPHRASE)
        .unwrap_or(false)
    {
        return Ok(());
    }
    // First boot: generate fresh passphrase. 32 random bytes hex-encoded
    // (same format the faucet binary used when generating itself).
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let passphrase = hex::encode(bytes);
    ks.store_raw(
        noble_crypto::SCHEME_FAUCET_PASSPHRASE,
        passphrase.as_bytes(),
        &wallet_pass,
    )
    .map_err(|e| format!("store faucet passphrase: {e}"))?;
    tracing::info!(
        task = "faucet_passphrase",
        "faucet passphrase bootstrapped in keystore"
    );
    Ok(())
}

// ── State-shaped wrappers for the RPC impl ─────────────────────────────
// These stay generic over `S` for the existing `Arc<ApiState<S>>` call
// sites (RPC method bodies). They delegate to the parameter-shaped
// helpers above.

fn read_or_create_faucet_admin_token<S>(
    state: &Arc<ApiState<S>>,
) -> Result<(String, u64, String), ApiError>
where
    S: noble_storage::StorageEngine + Send + Sync + 'static,
{
    read_or_create_faucet_admin_token_with(&state.wallet_keystore, &state.chain_meta)
        .map_err(ApiError::Internal)
}

fn rotate_faucet_admin_token_inner<S>(
    state: &Arc<ApiState<S>>,
) -> Result<(String, u64, String), ApiError>
where
    S: noble_storage::StorageEngine + Send + Sync + 'static,
{
    rotate_faucet_admin_token_with(&state.wallet_keystore, &state.chain_meta)
        .map_err(ApiError::Internal)
}
