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

        // Derive Bitcoin display addresses
        let noble_crypto::NoblePublicKey::Secp256k1(ref raw) = pubkey;
        let bitcoin_addresses = if let Ok(compressed) = <&[u8; 33]>::try_from(raw.as_slice()) {
            derive_bitcoin_addresses(compressed)
        } else {
            vec![]
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
        let NoblePublicKey::Secp256k1(ref bytes) = pubkey;
        let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
        let (private_key_hex, public_key_hex, wire_hex_str, btc_addrs) = (
            None, // Private key stays in keystore — not exposed over RPC
            Some(hex::encode(key_bytes)),
            Some(hex::encode(pubkey.to_wire_bytes())),
            Some(derive_bitcoin_addresses(&key)),
        );

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
            let NoblePublicKey::Secp256k1(ref bytes) = existing_pk;
            let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
            let addrs = derive_bitcoin_addresses(&key);
            let p2wpkh = addrs
                .iter()
                .find(|a| a.address_type == "p2wpkh")
                .map(|a| a.address.clone())
                .unwrap_or_default();
            let (bitcoin_address, bitcoin_addresses) = (p2wpkh, addrs);
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
        let NoblePublicKey::Secp256k1(ref bytes) = pubkey;
        let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
        let addrs = derive_bitcoin_addresses(&key);
        let p2wpkh = addrs
            .iter()
            .find(|a| a.address_type == "p2wpkh")
            .map(|a| a.address.clone())
            .unwrap_or_default();
        let (bitcoin_address, bitcoin_addresses) = (p2wpkh, addrs);

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
                let NoblePublicKey::Secp256k1(ref bytes) = pk;
                let bitcoin_addresses = if let Ok(key) = <[u8; 33]>::try_from(bytes.as_slice()) {
                    derive_bitcoin_addresses(&key)
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
        let NoblePublicKey::Secp256k1(ref bytes) = pubkey;
        let key: [u8; 33] = bytes.as_slice().try_into().unwrap_or([0u8; 33]);
        let (public_key_hex, wire_hex_str, btc_addrs) = (
            Some(hex::encode(key_bytes)),
            Some(hex::encode(pubkey.to_wire_bytes())),
            Some(derive_bitcoin_addresses(&key)),
        );

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
        use noble_core::NobleAddress;

        // Get wallet's public key.
        let wallet_keys = {
            let ks = self.wallet_keystore.lock();
            ks.list_keys().unwrap_or_default()
        };
        let Some(wallet_pk) = wallet_keys.into_iter().next() else {
            return Ok(WalletTransactionsResponse { transactions: vec![] });
        };

        // Derive ALL 3 address variants for this key.
        let noble_addr = NobleAddress::Noble(wallet_pk.clone());
        let hash160_addr = NobleAddress::BitcoinHash160(
            noble_crypto::bitcoin_addr::hash160(wallet_pk.key_bytes()),
        );
        let taproot_addr = NobleAddress::bitcoin_taproot_for_pubkey(&wallet_pk)
            .unwrap_or_else(|| {
                // Fallback: raw x-only (shouldn't happen for valid secp256k1 keys)
                let kb = wallet_pk.key_bytes();
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&kb[1..33]);
                NobleAddress::BitcoinTaproot(xonly)
            });

        // All wire byte sets for "is this address ours?" checks.
        let my_wires: Vec<Vec<u8>> = vec![
            noble_addr.to_wire_bytes(),
            hash160_addr.to_wire_bytes(),
            taproot_addr.to_wire_bytes(),
        ];
        let is_ours = |wire: &[u8]| my_wires.iter().any(|w| w.as_slice() == wire);

        let storage = self.storage.read();
        let tip_height = storage.get_chain_tip().ok().flatten().map(|t| t.height).unwrap_or(0);

        // Query history from ALL three address variants, deduplicate, sort newest first.
        let mut seen = std::collections::HashSet::new();
        let mut all_tx_ids: Vec<(noble_crypto::Hash256, u64)> = Vec::new();
        for addr in [&noble_addr, &hash160_addr, &taproot_addr] {
            let ids = match storage.get_address_history(addr, 0, 1000) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(task = "wallet_txs", "address history query failed: {e}");
                    continue;
                }
            };
            for id in ids {
                if !seen.insert(id) { continue; } // deduplicate
                match storage.get_transaction_location(&id) {
                    Ok((h, _)) => all_tx_ids.push((id, h)),
                    Err(e) => {
                        tracing::warn!(task = "wallet_txs", "tx location lookup failed for {}: {e}", hex::encode(id.as_bytes()));
                    }
                }
            }
        }
        all_tx_ids.sort_by(|a, b| b.1.cmp(&a.1)); // newest first

        // Enrich each transaction.
        let mut entries = Vec::new();
        for (tx_id, height) in &all_tx_ids {
            let tx = match storage.get_transaction(tx_id) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(task = "wallet_txs", "failed to read tx {}: {e}", hex::encode(tx_id.as_bytes()));
                    continue;
                }
            };

            let tx_id_hex = hex::encode(tx_id.as_bytes());
            let confirmations = tip_height.saturating_sub(*height);
            let status = confirmation_status_label(Some(confirmations));

            // Build the base TransactionResponse (reuse the shared function).
            let mut resp = tx_to_response(&tx, &tx_id_hex);
            resp.confirmations = Some(confirmations);
            resp.confirmation_status = Some(status.clone());

            // Compute fee from input UTXOs (same pattern as get_transaction).
            if !tx.is_coinbase() {
                let mut input_total: u64 = 0;
                let mut all_resolved = true;
                for inp in &tx.inputs {
                    match storage.get_transaction(&inp.prev_output.txid) {
                        Ok(prev_tx) => {
                            if let Some(out) = prev_tx.outputs.get(inp.prev_output.vout as usize) {
                                input_total += out.value;
                            } else {
                                all_resolved = false;
                            }
                        }
                        Err(_) => { all_resolved = false; }
                    }
                }
                if all_resolved && input_total > 0 {
                    resp.fee = Some(input_total.saturating_sub(tx.total_output_value()));
                }
            }

            // Determine if we are the sender.
            let is_sender = tx.issuer_sig.to_noble_public_key().ok()
                .map(|pk| {
                    let sender_wire = NobleAddress::Noble(pk).to_wire_bytes();
                    is_ours(&sender_wire)
                })
                .unwrap_or(false);

            // Type-aware direction, amount, counterparty.
            let tx_type_names = [
                (0x00, "Notarization"), (0x01, "Transfer"), (0x02, "Key Rotation"),
                (0x03, "Badge Proposal"), (0x04, "Badge Vote"), (0x05, "Badge Revocation"),
                (0x06, "Locked"), (0x07, "Unlocking"), (0x10, "Coinbase"),
            ];
            let type_label = tx_type_names.iter()
                .find(|(code, _)| *code == tx.tx_type)
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| format!("Type 0x{:02x}", tx.tx_type));

            let (direction, amount, counterparty) = if tx.is_coinbase() {
                // Coinbase: sum outputs going to any of our addresses.
                let reward: u64 = tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value)
                    .sum();
                ("incoming".to_string(), reward, Some("Block Reward".to_string()))
            } else if tx.tx_type == 0x01 {
                // Transfer
                if is_sender {
                    let sent: u64 = tx.outputs.iter()
                        .filter(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    let cp = tx.outputs.iter()
                        .find(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.address.to_display_address());
                    ("outgoing".to_string(), sent, cp)
                } else {
                    let received: u64 = tx.outputs.iter()
                        .filter(|o| is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    let cp = tx.issuer_sig.to_noble_public_key().ok()
                        .map(|pk| noble_crypto::noble_addr::encode(&pk));
                    ("incoming".to_string(), received, cp)
                }
            } else if tx.tx_type == 0x00 || tx.tx_type == 0x06 || tx.tx_type == 0x07 {
                // Notarization, Locked, Unlocking
                let fee_amount = resp.fee.unwrap_or(0);
                if is_sender {
                    ("outgoing".to_string(), fee_amount, Some("Self (Document)".to_string()))
                } else {
                    let cp = tx.issuer_sig.to_noble_public_key().ok()
                        .map(|pk| noble_crypto::noble_addr::encode(&pk));
                    ("incoming".to_string(), fee_amount, cp)
                }
            } else if tx.tx_type == 0x02 {
                // Key Rotation
                ("self".to_string(), 0, Some("Key Rotation".to_string()))
            } else {
                // Badge types (0x03-0x05)
                ("self".to_string(), 0, Some("Governance".to_string()))
            };

            entries.push(WalletTransactionEntry {
                tx_id: tx_id_hex,
                tx_type: tx.tx_type,
                type_label,
                direction,
                amount,
                counterparty,
                status,
                total_output: resp.total_output,
                transfer_value: resp.transfer_value,
                fee: resp.fee,
                checksum: resp.checksum.clone(),
                timestamp: tx.timestamp,
                signer: resp.signer.clone(),
                inputs: resp.inputs.clone(),
                outputs: resp.outputs.clone(),
                metadata: resp.metadata.clone(),
                has_encrypted_locator: resp.has_encrypted_locator,
                confirmations,
                block_height: Some(*height),
            });
        }

        // Prepend mempool pending txs from all 3 variants.
        let mut pending_entries = Vec::new();
        {
            let mempool = self.mempool.lock();
            let mut seen_pending = std::collections::HashSet::new();
            for addr in [&noble_addr, &hash160_addr, &taproot_addr] {
                for s in mempool.pending_tx_summaries(addr) {
                    if !seen_pending.insert(s.tx_id) { continue; }
                    pending_entries.push(WalletTransactionEntry {
                        tx_id: hex::encode(s.tx_id.as_bytes()),
                        tx_type: 0x01, // best guess for pending
                        type_label: "Pending Transfer".to_string(),
                        direction: "outgoing".to_string(),
                        amount: s.outputs_to_others,
                        counterparty: Some("Pending".to_string()),
                        status: "pending".to_string(),
                        total_output: s.outputs_to_others + s.outputs_to_self,
                        transfer_value: s.outputs_to_others,
                        fee: Some(s.fee),
                        checksum: String::new(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        signer: noble_crypto::noble_addr::encode(&wallet_pk),
                        inputs: vec![],
                        outputs: vec![],
                        metadata: vec![],
                        has_encrypted_locator: false,
                        confirmations: 0,
                        block_height: None,
                    });
                }
            }
        }

        // Pending first, then confirmed (newest first).
        pending_entries.extend(entries);
        Ok(WalletTransactionsResponse { transactions: pending_entries })
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
