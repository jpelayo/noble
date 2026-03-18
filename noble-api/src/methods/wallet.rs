// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet-related RPC methods: createAddress, walletUnlock, walletLock,
//! getWalletInfo, walletSendTransfer, submitDocumentBatch.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_crypto::{NoblePublicKey, SCHEME_SECP256K1};
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait WalletApi {
    /// Create a new address (key pair) in the wallet.
    #[method(name = "createAddress")]
    async fn create_address(
        &self,
        scheme_id: u8,
        passphrase: String,
    ) -> Result<CreateAddressResponse, ErrorObjectOwned>;

    /// Unlock the wallet for a given timeout (seconds).
    #[method(name = "walletUnlock")]
    async fn wallet_unlock(
        &self,
        passphrase: String,
        timeout_secs: u64,
    ) -> Result<WalletUnlockResponse, ErrorObjectOwned>;

    /// Lock the wallet immediately.
    #[method(name = "walletLock")]
    async fn wallet_lock(&self) -> Result<bool, ErrorObjectOwned>;

    /// Get wallet info: unlock status, expiry, key count.
    #[method(name = "getWalletInfo")]
    async fn get_wallet_info(&self) -> Result<WalletInfoResponse, ErrorObjectOwned>;

    /// Build, sign, and submit a transfer transaction.
    ///
    /// `source_address` optionally specifies which balance bucket to debit.
    /// If omitted and `from` is secp256k1, the node auto-selects Noble first,
    /// then Hash160 fallback.
    #[method(name = "walletSendTransfer")]
    async fn wallet_send_transfer(
        &self,
        from: String,
        to: String,
        amount: u64,
        fee: Option<u64>,
        memo: Option<String>,
        source_address: Option<String>,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned>;

    /// Submit a batch of document checksums for notarization.
    /// Up to 100 checksums per call. Best-effort: each is processed independently.
    #[method(name = "submitDocumentBatch")]
    async fn submit_document_batch(
        &self,
        signer: String,
        checksums: Vec<String>,
        fee_per_tx: Option<u64>,
    ) -> Result<SubmitBatchResponse, ErrorObjectOwned>;

    /// Generate a new BIP-39 mnemonic (12 or 24 words) and create a key from it.
    /// Returns the mnemonic phrase and the derived address.
    /// The user MUST back up the mnemonic — it cannot be recovered from the node.
    #[method(name = "generateMnemonic")]
    async fn generate_mnemonic(
        &self,
        word_count: Option<u32>,
        passphrase: String,
    ) -> Result<GenerateMnemonicResponse, ErrorObjectOwned>;

    /// Import an existing BIP-39 mnemonic phrase and derive the corresponding key.
    /// If the key already exists, returns it without re-encrypting.
    #[method(name = "importMnemonic")]
    async fn import_mnemonic(
        &self,
        mnemonic: String,
        passphrase: String,
    ) -> Result<ImportMnemonicResponse, ErrorObjectOwned>;

    /// Import a secp256k1 private key (WIF or hex) into the wallet.
    /// Returns the public key and derived Bitcoin address.
    #[method(name = "importSecp256k1Key")]
    async fn import_secp256k1_key(
        &self,
        key_input: String,
        passphrase: String,
    ) -> Result<ImportKeyResponse, ErrorObjectOwned>;

    /// List all public keys in the wallet keystore.
    ///
    /// Does not require the wallet to be unlocked — reads key filenames only.
    #[method(name = "listAddresses")]
    async fn list_addresses(&self) -> Result<ListAddressesResponse, ErrorObjectOwned>;

    /// Delete a wallet key from the keystore.
    /// Requires the wallet passphrase for verification.
    /// Refuses to delete the active gateway key.
    #[method(name = "deleteAddress")]
    async fn delete_address(
        &self,
        pubkey_hex: String,
        passphrase: String,
    ) -> Result<DeleteAddressResponse, ErrorObjectOwned>;

    /// Get wallet transaction history (stub — returns empty list).
    #[method(name = "getWalletTransactions")]
    async fn get_wallet_transactions(&self) -> Result<WalletTransactionsResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> WalletApiServer for Arc<ApiState<S>> {
    async fn create_address(
        &self,
        scheme_id: u8,
        _passphrase: String,
    ) -> Result<CreateAddressResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        let mut keystore = self.wallet_keystore.lock();

        // Guard: reject if a key of the same scheme already exists
        let existing = keystore.list_keys().unwrap_or_default();
        if existing.iter().any(|k| k.scheme_id() == scheme_id) {
            return Err(ApiError::InvalidParam(
                "A wallet key with this scheme already exists. Delete it first to create a new one.".into(),
            ).into());
        }

        let pubkey = keystore
            .create_key(scheme_id, &passphrase)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        // Derive Bitcoin display addresses for secp256k1 keys
        let bitcoin_addresses = match &pubkey {
            noble_crypto::NoblePublicKey::Secp256k1(raw) => {
                if let Ok(compressed) = <&[u8; 33]>::try_from(raw.as_slice()) {
                    derive_bitcoin_addresses(compressed)
                } else {
                    vec![]
                }
            }
            _ => vec![],
        };

        Ok(CreateAddressResponse {
            address: pubkey.to_address(),
            scheme_id: pubkey.scheme_id(),
            bitcoin_addresses,
        })
    }

    async fn wallet_unlock(
        &self,
        _passphrase: String,
        timeout_secs: u64,
    ) -> Result<WalletUnlockResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        {
            let mut keystore = self.wallet_keystore.lock();
            keystore.unlock(&passphrase).map_err(|e| match e {
                noble_wallet::WalletError::InvalidPassphrase => ApiError::InvalidPassphrase,
                other => ApiError::Internal(other.to_string()),
            })?;
        }

        let mut state = self.wallet_state.lock();
        let expires_at = state.unlock(timeout_secs);

        Ok(WalletUnlockResponse {
            unlocked: true,
            expires_at,
        })
    }

    async fn wallet_lock(&self) -> Result<bool, ErrorObjectOwned> {
        {
            let mut keystore = self.wallet_keystore.lock();
            keystore.lock();
        }
        {
            let mut state = self.wallet_state.lock();
            state.lock();
        }
        Ok(true)
    }

    async fn get_wallet_info(&self) -> Result<WalletInfoResponse, ErrorObjectOwned> {
        let keystore = self.wallet_keystore.lock();
        let state = self.wallet_state.lock();

        let keys = keystore.list_keys().map_err(|e| {
            ErrorObjectOwned::owned(-32603, format!("keystore read failed: {e}"), None::<()>)
        })?;
        let key_count = keys.len();

        // Sum balances across all wallet keys and all address buckets
        let storage = self.storage.read();
        let mempool = self.mempool.lock();
        let mut total_balance = 0u64;
        let mut total_pending = 0u64;
        let mut noble_bal = 0u64;
        let mut hash160_bal = 0u64;
        let mut taproot_bal = 0u64;

        // Collect all keys to query: wallet keystore keys + validator key (if not already included).
        let mut all_keys: Vec<noble_crypto::NoblePublicKey> = keys.clone();
        if let Some(ref vk_hex) = *self.validator_pubkey.read() {
            match hex::decode(vk_hex) {
                Ok(vk_bytes) => match noble_crypto::NoblePublicKey::from_wire_bytes(&vk_bytes) {
                    Ok(vk) => {
                        let already = all_keys.iter().any(|k| k.to_wire_bytes() == vk.to_wire_bytes());
                        if !already {
                            all_keys.push(vk);
                        }
                    }
                    Err(e) => tracing::warn!("validator_pubkey wire decode failed: {e}"),
                },
                Err(e) => tracing::warn!("validator_pubkey hex decode failed: {e}"),
            }
        }

        for pk in &all_keys {
            // Noble bucket (all key types)
            let nb = storage
                .get_balance(&noble_core::NobleAddress::Noble(pk.clone()))
                .unwrap_or_else(|e| {
                    tracing::warn!("balance read failed for Noble bucket: {e}");
                    0
                });
            noble_bal = noble_bal.saturating_add(nb);
            total_balance = total_balance.saturating_add(nb);

            // Hash160 + Taproot buckets (secp256k1 keys only)
            if let Some(h160_addr) = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                let hb = storage.get_balance(&h160_addr).unwrap_or_else(|e| {
                    tracing::warn!("balance read failed for Hash160 bucket: {e}");
                    0
                });
                hash160_bal = hash160_bal.saturating_add(hb);
                total_balance = total_balance.saturating_add(hb);
            }
            if let Some(tap_addr) = noble_core::NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                let tb = storage.get_balance(&tap_addr).unwrap_or_else(|e| {
                    tracing::warn!("balance read failed for Taproot bucket: {e}");
                    0
                });
                taproot_bal = taproot_bal.saturating_add(tb);
                total_balance = total_balance.saturating_add(tb);
            }

            // Pending debits per bucket (bucket-aware)
            let noble_addr = noble_core::NobleAddress::Noble(pk.clone());
            total_pending = total_pending.saturating_add(mempool.pending_debit_for_address(&noble_addr));

            if let Some(h160_addr) = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                total_pending = total_pending.saturating_add(mempool.pending_debit_for_address(&h160_addr));
            }
            if let Some(tap_addr) = noble_core::NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                total_pending = total_pending.saturating_add(mempool.pending_debit_for_address(&tap_addr));
            }
        }
        drop(mempool);
        drop(storage);

        // Only include bucket breakdown if there are non-zero Bitcoin balances
        let has_bitcoin = hash160_bal > 0 || taproot_bal > 0;

        Ok(WalletInfoResponse {
            unlocked: state.is_unlocked(),
            expires_at: state.expires_at_unix(),
            key_count,
            balance: total_balance,
            available: total_balance.saturating_sub(total_pending),
            pending: total_pending,
            noble_balance: if has_bitcoin { Some(noble_bal) } else { None },
            hash160_balance: if has_bitcoin { Some(hash160_bal) } else { None },
            taproot_balance: if has_bitcoin { Some(taproot_bal) } else { None },
        })
    }

    async fn wallet_send_transfer(
        &self,
        _from: String,
        _to: String,
        _amount: u64,
        _fee: Option<u64>,
        _memo: Option<String>,
        _source_address: Option<String>,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // DEPRECATED: The node no longer holds spending keys.
        // Build and sign transactions locally, then submit via noble_submitTransaction.
        Err(ApiError::InvalidParam(
            "walletSendTransfer is deprecated. Build and sign transfers locally \
             (using noble-tool wallet or the faucet wallet), then submit via \
             noble_submitTransaction."
                .into(),
        )
        .into())
    }

    async fn generate_mnemonic(
        &self,
        word_count: Option<u32>,
        _passphrase: String,
    ) -> Result<GenerateMnemonicResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        let wc = word_count.unwrap_or(24) as usize;
        if wc != 12 && wc != 24 {
            return Err(ApiError::InvalidParam("word_count must be 12 or 24".into()).into());
        }

        let mut keystore = self.wallet_keystore.lock();

        // Guard: reject if any secp256k1 key already exists
        let existing = keystore.list_keys().unwrap_or_default();
        if existing.iter().any(|k| k.scheme_id() == SCHEME_SECP256K1) {
            return Err(ApiError::InvalidParam(
                "A secp256k1 wallet key already exists. Delete it first to generate a new one.".into(),
            ).into());
        }

        // Write validator.key alongside the wallet key (same secret, one derivation).
        let vkey_path = self.data_dir.as_ref().map(|d| d.join("validator.key"));
        let (mnemonic, pubkey) = if let Some(ref vkp) = vkey_path {
            keystore
                .create_key_from_mnemonic_with_validator(wc, &passphrase, vkp, &self.chain_meta)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        } else {
            keystore
                .create_key_from_mnemonic(wc, &passphrase)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        };

        let key_bytes = pubkey.key_bytes();
        let (private_key_hex, public_key_hex, wire_hex_str, btc_addrs) =
            if let NoblePublicKey::Secp256k1(ref bytes) = pubkey {
                let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
                (
                    None, // Private key stays in keystore — not exposed over RPC
                    Some(hex::encode(key_bytes)),
                    Some(hex::encode(pubkey.to_wire_bytes())),
                    Some(derive_bitcoin_addresses(&key)),
                )
            } else {
                (None, Some(hex::encode(key_bytes)), Some(hex::encode(pubkey.to_wire_bytes())), None)
            };

        Ok(GenerateMnemonicResponse {
            mnemonic,
            address: pubkey.to_address(),
            scheme_id: pubkey.scheme_id(),
            word_count: wc,
            private_key: private_key_hex,
            public_key: public_key_hex,
            wire_hex: wire_hex_str,
            bitcoin_addresses: btc_addrs,
        })
    }

    async fn import_secp256k1_key(
        &self,
        key_input: String,
        _passphrase: String,
    ) -> Result<ImportKeyResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        let mut keystore = self.wallet_keystore.lock();

        // Guard: if a secp256k1 key already exists, return it (idempotent import)
        let existing = keystore.list_keys().unwrap_or_default();
        if let Some(existing_pk) = existing.iter().find(|k| k.scheme_id() == SCHEME_SECP256K1) {
            let (bitcoin_address, bitcoin_addresses) =
                if let NoblePublicKey::Secp256k1(ref bytes) = existing_pk {
                    let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
                    let addrs = derive_bitcoin_addresses(&key);
                    let p2wpkh = addrs
                        .iter()
                        .find(|a| a.address_type == "p2wpkh")
                        .map(|a| a.address.clone())
                        .unwrap_or_default();
                    (p2wpkh, addrs)
                } else {
                    (String::new(), vec![])
                };
            return Ok(ImportKeyResponse {
                public_key: existing_pk.to_address(),
                bitcoin_address,
                bitcoin_addresses,
            });
        }

        let pubkey = keystore
            .import_secp256k1_key(&key_input, &passphrase)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        // Derive Bitcoin display addresses
        let (bitcoin_address, bitcoin_addresses) =
            if let NoblePublicKey::Secp256k1(ref bytes) = pubkey {
                let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
                let addrs = derive_bitcoin_addresses(&key);
                let p2wpkh = addrs
                    .iter()
                    .find(|a| a.address_type == "p2wpkh")
                    .map(|a| a.address.clone())
                    .unwrap_or_default();
                (p2wpkh, addrs)
            } else {
                (String::new(), vec![])
            };

        Ok(ImportKeyResponse {
            public_key: pubkey.to_address(),
            bitcoin_address,
            bitcoin_addresses,
        })
    }

    async fn list_addresses(&self) -> Result<ListAddressesResponse, ErrorObjectOwned> {
        let keystore = self.wallet_keystore.lock();
        let keys = keystore
            .list_keys()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let entries = keys
            .into_iter()
            .map(|pk| {
                let scheme = match pk.scheme_id() {
                    SCHEME_SECP256K1 => "secp256k1",
                    _ => "unknown",
                };
                let bitcoin_addresses = if let NoblePublicKey::Secp256k1(ref bytes) = pk {
                    if let Ok(key) = <[u8; 33]>::try_from(bytes.as_slice()) {
                        derive_bitcoin_addresses(&key)
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                WalletKeyEntry {
                    pubkey_hex: pk.to_address(),
                    scheme: scheme.to_string(),
                    bitcoin_addresses,
                }
            })
            .collect();
        Ok(ListAddressesResponse { keys: entries })
    }

    async fn import_mnemonic(
        &self,
        mnemonic: String,
        _passphrase: String,
    ) -> Result<ImportMnemonicResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        let mut keystore = self.wallet_keystore.lock();

        // Check if key already exists by trying to recover
        let existing_keys: Vec<_> = keystore.list_keys().unwrap_or_default();
        // Write validator.key alongside the wallet key.
        let vkey_path = self.data_dir.as_ref().map(|d| d.join("validator.key"));
        let pubkey = if let Some(ref vkp) = vkey_path {
            keystore
                .recover_from_mnemonic_with_validator(&mnemonic, &passphrase, vkp, &self.chain_meta)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        } else {
            keystore
                .recover_from_mnemonic(&mnemonic, &passphrase)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        };

        let already_exists = existing_keys
            .iter()
            .any(|k| k.to_wire_bytes() == pubkey.to_wire_bytes());

        let key_bytes = pubkey.key_bytes();
        let (public_key_hex, wire_hex_str, btc_addrs) =
            if let NoblePublicKey::Secp256k1(ref bytes) = pubkey {
                let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
                (
                    Some(hex::encode(key_bytes)),
                    Some(hex::encode(pubkey.to_wire_bytes())),
                    Some(derive_bitcoin_addresses(&key)),
                )
            } else {
                (Some(hex::encode(key_bytes)), Some(hex::encode(pubkey.to_wire_bytes())), None)
            };

        Ok(ImportMnemonicResponse {
            address: pubkey.to_address(),
            scheme_id: pubkey.scheme_id(),
            already_exists,
            private_key: None, // Private key stays in keystore
            public_key: public_key_hex,
            wire_hex: wire_hex_str,
            bitcoin_addresses: btc_addrs,
        })
    }

    async fn delete_address(
        &self,
        pubkey_hex: String,
        _passphrase: String,
    ) -> Result<DeleteAddressResponse, ErrorObjectOwned> {
        let passphrase = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&self.chain_meta));
        // Parse the public key
        let pubkey = parse_pubkey(&pubkey_hex)?;

        // Refuse to delete the active gateway key
        {
            let gw = self.gateway_key.read();
            if let Some(ref gw_bytes) = *gw {
                if pubkey.to_wire_bytes() == *gw_bytes {
                    return Err(ApiError::InvalidParam(
                        "Cannot delete the active gateway key. Change gateway key first.".into(),
                    ).into());
                }
            }
        }

        // Delete the key (verifies passphrase internally)
        let mut keystore = self.wallet_keystore.lock();
        keystore
            .delete_key(&pubkey, &passphrase)
            .map_err(|e| match e {
                noble_wallet::WalletError::InvalidPassphrase => ApiError::InvalidPassphrase,
                noble_wallet::WalletError::KeyNotFound(k) => {
                    ApiError::InvalidParam(format!("Key not found: {k}"))
                }
                other => ApiError::Internal(other.to_string()),
            })?;

        Ok(DeleteAddressResponse {
            success: true,
            message: format!("Key {} deleted.", &pubkey_hex[..pubkey_hex.len().min(16)]),
        })
    }

    async fn get_wallet_transactions(&self) -> Result<WalletTransactionsResponse, ErrorObjectOwned> {
        // Stub: full implementation requires a chain-scanning address index.
        Ok(WalletTransactionsResponse {
            transactions: vec![],
        })
    }

    async fn submit_document_batch(
        &self,
        _signer: String,
        _checksums: Vec<String>,
        _fee_per_tx: Option<u64>,
    ) -> Result<SubmitBatchResponse, ErrorObjectOwned> {
        // DEPRECATED: The node no longer holds spending keys.
        // Build and sign notarization transactions locally, then submit via noble_submitTransaction.
        Err(ApiError::InvalidParam(
            "submitDocumentBatch is deprecated. Build and sign notarization transactions \
             locally (using noble-tool wallet), then submit via noble_submitTransaction."
                .into(),
        )
        .into())
    }
}

/// Derive all Bitcoin display addresses for a secp256k1 compressed public key.
fn derive_bitcoin_addresses(compressed: &[u8; 33]) -> Vec<BitcoinAddressEntry> {
    vec![
        BitcoinAddressEntry {
            address_type: "p2pkh".to_string(),
            address: noble_crypto::bitcoin_addr::pubkey_to_p2pkh(compressed, true),
        },
        BitcoinAddressEntry {
            address_type: "p2wpkh".to_string(),
            address: noble_crypto::bitcoin_addr::pubkey_to_p2wpkh(compressed, true),
        },
        BitcoinAddressEntry {
            address_type: "p2tr".to_string(),
            address: noble_crypto::bitcoin_addr::pubkey_to_p2tr(compressed, true),
        },
    ]
}
