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
    /// When `addresses_only=true`, skip the validator key — only include
    /// wallet keystore keys. Used by client apps whose key differs from the node.
    #[method(name = "getWalletInfo")]
    async fn get_wallet_info(&self, addresses_only: Option<bool>) -> Result<WalletInfoResponse, ErrorObjectOwned>;

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

    /// Get wallet transaction history.
    ///
    /// `addresses` — optional list of additional addresses (bech32m or hex wire)
    /// to include in the search. Useful when the client's wallet key differs
    /// from the node's keystore (e.g., remote client with its own Keychain).
    #[method(name = "getWalletTransactions")]
    async fn get_wallet_transactions(&self, addresses: Option<Vec<String>>, addresses_only: Option<bool>) -> Result<WalletTransactionsResponse, ErrorObjectOwned>;

    /// Atomic wallet snapshot: balance + transactions under a single storage read lock.
    /// Guarantees chain_height is identical for immature classification and confirmation counts.
    #[method(name = "getWalletSnapshot")]
    async fn get_wallet_snapshot(&self, address: String) -> Result<WalletSnapshotResponse, ErrorObjectOwned>;
}

/// Collect all public keys the wallet considers "ours":
/// wallet keystore keys + validator key (if not already included).
/// Single source of truth — used by both get_wallet_info and get_wallet_transactions.
fn collect_wallet_keys<S: StorageEngine + Send + Sync + 'static>(state: &ApiState<S>) -> Vec<noble_crypto::NoblePublicKey> {
    let mut all_keys: Vec<noble_crypto::NoblePublicKey> = {
        let ks = state.wallet_keystore.lock();
        ks.list_keys().unwrap_or_default()
    };
    // Include the validator key if it's not already in the wallet keystore.
    if let Some(ref vk_hex) = *state.validator_pubkey.read() {
        if let Ok(vk_bytes) = hex::decode(vk_hex) {
            if let Ok(vk) = noble_crypto::NoblePublicKey::from_wire_bytes(&vk_bytes) {
                let already = all_keys.iter().any(|k| k.to_wire_bytes() == vk.to_wire_bytes());
                if !already {
                    all_keys.push(vk);
                }
            }
        }
    }
    all_keys
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

    async fn get_wallet_info(&self, addresses_only: Option<bool>) -> Result<WalletInfoResponse, ErrorObjectOwned> {
        let state = self.wallet_state.lock();

        let all_keys = if addresses_only.unwrap_or(false) {
            // Client mode: wallet keystore keys only (skip validator key).
            let ks = self.wallet_keystore.lock();
            ks.list_keys().unwrap_or_default()
        } else {
            // Node mode: all keys (wallet + validator).
            collect_wallet_keys(self)
        };
        let key_count = all_keys.len();

        // Sum balances across all wallet keys and all address buckets.
        // Also compute immature UTXO total (same pattern as getAddressBalance in address.rs).
        let storage = self.storage.read();
        let mempool = self.mempool.lock();
        let tip_height = storage.get_chain_tip().ok().flatten().map(|t| t.height).unwrap_or(0);
        let mut total_balance = 0u64;
        let mut total_immature = 0u64;
        let mut total_pending = 0u64;
        let mut noble_bal = 0u64;
        let mut hash160_bal = 0u64;
        let mut taproot_bal = 0u64;

        // Scan UTXOs per address to separate mature from immature.
        let scan_address = |addr: &noble_core::NobleAddress| -> (u64, u64) {
            let mut bal = 0u64;
            let mut immature = 0u64;
            for (_, entry) in storage.get_address_utxos(addr).unwrap_or_default() {
                bal = bal.saturating_add(entry.value);
                if !entry.is_mature(tip_height) {
                    immature = immature.saturating_add(entry.value);
                }
            }
            (bal, immature)
        };

        for pk in &all_keys {
            // Noble bucket (all key types)
            let noble_addr = noble_core::NobleAddress::Noble(pk.clone());
            let (nb, nb_imm) = scan_address(&noble_addr);
            noble_bal = noble_bal.saturating_add(nb);
            total_balance = total_balance.saturating_add(nb);
            total_immature = total_immature.saturating_add(nb_imm);

            // Hash160 + Taproot buckets (secp256k1 keys only)
            if let Some(h160_addr) = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                let (hb, hb_imm) = scan_address(&h160_addr);
                hash160_bal = hash160_bal.saturating_add(hb);
                total_balance = total_balance.saturating_add(hb);
                total_immature = total_immature.saturating_add(hb_imm);
            }
            if let Some(tap_addr) = noble_core::NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                let (tb, tb_imm) = scan_address(&tap_addr);
                taproot_bal = taproot_bal.saturating_add(tb);
                total_balance = total_balance.saturating_add(tb);
                total_immature = total_immature.saturating_add(tb_imm);
            }

            // Pending debits per bucket (bucket-aware)
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

        // available = total - immature - mempool_pending
        let available = total_balance
            .saturating_sub(total_immature)
            .saturating_sub(total_pending);

        Ok(WalletInfoResponse {
            unlocked: state.is_unlocked(),
            expires_at: state.expires_at_unix(),
            key_count,
            balance: total_balance,
            available,
            pending: total_pending,
            immature: total_immature,
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

    async fn get_wallet_transactions(&self, addresses: Option<Vec<String>>, addresses_only: Option<bool>) -> Result<WalletTransactionsResponse, ErrorObjectOwned> {
        use noble_core::NobleAddress;

        let mut all_addrs: Vec<NobleAddress> = Vec::new();
        let mut my_wires: Vec<Vec<u8>> = Vec::new();

        // When addresses_only=true, ONLY scan the provided addresses — skip node keystore/validator.
        // Used by client apps whose wallet key differs from the node's validator key.
        if !addresses_only.unwrap_or(false) {
            let all_keys = collect_wallet_keys(self);
            for pk in &all_keys {
                let noble_addr = NobleAddress::Noble(pk.clone());
                my_wires.push(noble_addr.to_wire_bytes());
                all_addrs.push(noble_addr);

                if let Some(h160) = NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                    my_wires.push(h160.to_wire_bytes());
                    all_addrs.push(h160);
                }
                if let Some(tap) = NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                    my_wires.push(tap.to_wire_bytes());
                    all_addrs.push(tap);
                }
            }
        }

        // Include client-provided addresses (bech32m or hex wire).
        if let Some(extra_addrs) = addresses {
            for addr_str in &extra_addrs {
                if let Ok(addr) = crate::types::parse_address(addr_str) {
                    let wire = addr.to_wire_bytes();
                    if !my_wires.contains(&wire) {
                        my_wires.push(wire);
                        all_addrs.push(addr);
                    }
                }
            }
        }

        if all_addrs.is_empty() {
            return Ok(WalletTransactionsResponse { transactions: vec![] });
        }
        let is_ours = |wire: &[u8]| my_wires.iter().any(|w| w.as_slice() == wire);


        let storage = self.storage.read();
        let tip_height = storage.get_chain_tip().ok().flatten().map(|t| t.height).unwrap_or(0);

        // Query history from ALL three address variants, deduplicate, sort newest first.
        let mut seen = std::collections::HashSet::new();
        let mut all_tx_ids: Vec<(noble_crypto::Hash256, u64)> = Vec::new();
        for addr in &all_addrs {
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
            let confirmations = tip_height.saturating_sub(*height) + 1;
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
                        Err(_) => { all_resolved = false; } // pruned UTXO — fee will be None
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

            // Type-aware direction and amount.
            let tx_type_names = [
                (0x00, "Notarization"), (0x01, "Transfer"), (0x02, "Key Rotation"),
                (0x03, "Badge Proposal"), (0x04, "Badge Vote"), (0x05, "Badge Revocation"),
                (0x06, "Locked"), (0x07, "Unlocking"), (0x10, "Block Reward"),
                (0x11, "Fee Distribution"),
            ];
            let type_label = tx_type_names.iter()
                .find(|(code, _)| *code == tx.tx_type)
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| format!("Type 0x{:02x}", tx.tx_type));

            let (direction, amount) = if tx.tx_type == 0x11 {
                // Fee Distribution: fees collected from block transactions.
                let fee_income: u64 = tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value)
                    .sum();
                ("incoming".to_string(), fee_income)
            } else if tx.is_coinbase() {
                let reward: u64 = tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value)
                    .sum();
                ("incoming".to_string(), reward)
            } else if tx.tx_type == 0x01 {
                // Transfer
                if is_sender {
                    let sent: u64 = tx.outputs.iter()
                        .filter(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    // If sender AND recipient, add a second incoming entry for the received portion
                    let received: u64 = tx.outputs.iter()
                        .filter(|o| is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    if received > 0 {
                        let mut incoming_resp = resp.clone();
                        incoming_resp.direction = Some("incoming".to_string());
                        incoming_resp.amount = Some(received);
                        incoming_resp.type_label = Some(type_label.clone());
                        incoming_resp.block_height = Some(*height);
                        incoming_resp.status = Some(status.clone());
                        entries.push(incoming_resp);
                    }
                    ("outgoing".to_string(), sent)
                } else {
                    let received: u64 = tx.outputs.iter()
                        .filter(|o| is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    ("incoming".to_string(), received)
                }
            } else if tx.tx_type == 0x00 || tx.tx_type == 0x06 || tx.tx_type == 0x07 {
                // Notarization, Locked, Unlocking
                let fee_amount = resp.fee.unwrap_or(0);
                if is_sender {
                    ("outgoing".to_string(), fee_amount)
                } else {
                    ("incoming".to_string(), fee_amount)
                }
            } else if tx.tx_type == 0x02 {
                ("self".to_string(), 0)
            } else {
                ("self".to_string(), 0)
            };

            resp.direction = Some(direction);
            resp.amount = Some(amount);
            resp.type_label = Some(type_label);
            resp.block_height = Some(*height);
            resp.status = Some(status);
            entries.push(resp);
        }

        // Prepend mempool pending txs — both sent BY and sent TO the wallet.
        let mut pending_entries = Vec::new();
        {
            let mempool = self.mempool.lock();
            let mut seen_pending = std::collections::HashSet::new();

            let mempool_count = mempool.len();
            tracing::debug!(task = "wallet_txs", "mempool scan: {} entries, {} wallet wire variants", mempool_count, my_wires.len());
            for (i, w) in my_wires.iter().enumerate() {
                tracing::debug!(task = "wallet_txs", "  my_wire[{}] = {} ({} bytes)", i, hex::encode(w), w.len());
            }

            for entry in mempool.iter_by_fee_rate_desc() {
                if !seen_pending.insert(entry.tx_id) { continue; }

                // Check if we are the sender.
                let issuer_wire = entry.tx.issuer_sig.to_noble_public_key().ok()
                    .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes());
                let sender_is_ours = issuer_wire.as_ref()
                    .map(|w| is_ours(w))
                    .unwrap_or(false);

                // Check if any output goes to us (incoming).
                let value_to_us: u64 = entry.tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value)
                    .sum();

                tracing::debug!(
                    task = "wallet_txs",
                    "mempool tx {} type={} issuer_wire={} sender_ours={} value_to_us={}",
                    hex::encode(entry.tx_id.as_bytes()),
                    entry.tx.tx_type,
                    issuer_wire.as_ref().map(|w| hex::encode(w)).unwrap_or_else(|| "ERR".into()),
                    sender_is_ours,
                    value_to_us,
                );

                if !sender_is_ours && value_to_us == 0 {
                    continue; // Not our tx — skip
                }

                let (direction, amount) = if sender_is_ours {
                    let sent: u64 = entry.tx.outputs.iter()
                        .filter(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value)
                        .sum();
                    ("outgoing", sent)
                } else {
                    ("incoming", value_to_us)
                };

                let tx_type_names = [
                    (0x00, "Notarization"), (0x01, "Transfer"), (0x02, "Key Rotation"),
                    (0x03, "Badge Proposal"), (0x04, "Badge Vote"), (0x05, "Badge Revocation"),
                    (0x06, "Locked"), (0x07, "Unlocking"), (0x10, "Block Reward"),
                    (0x11, "Fee Distribution"),
                ];
                let type_label = tx_type_names.iter()
                    .find(|(code, _)| *code == entry.tx.tx_type)
                    .map(|(_, name)| format!("Pending {name}"))
                    .unwrap_or_else(|| "Pending".to_string());

                let tx_id_hex = hex::encode(entry.tx_id.as_bytes());
                let mut resp = tx_to_response(&entry.tx, &tx_id_hex);
                resp.fee = Some(entry.fee);
                resp.confirmation_status = Some("pending".to_string());
                resp.confirmations = Some(0);
                resp.direction = Some(direction.to_string());
                resp.amount = Some(amount);
                resp.type_label = Some(type_label.clone());
                resp.block_height = None;
                resp.status = Some("pending".to_string());
                pending_entries.push(resp.clone());

                // If sender AND recipient, add a second incoming entry
                if sender_is_ours && value_to_us > 0 {
                    let mut incoming_resp = resp;
                    incoming_resp.direction = Some("incoming".to_string());
                    incoming_resp.amount = Some(value_to_us);
                    incoming_resp.type_label = Some(type_label);
                    pending_entries.push(incoming_resp);
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

    async fn get_wallet_snapshot(&self, address: String) -> Result<WalletSnapshotResponse, ErrorObjectOwned> {
        use noble_core::NobleAddress;

        let addr = parse_address(&address)?;

        // ── Single storage read lock for both balance and transactions ──
        let storage = self.storage.read();
        let chain_height = storage.get_chain_tip().ok().flatten().map(|t| t.height).unwrap_or(0);

        // ── Balance (same logic as getAddressBalance) ──
        let total_balance = storage.get_balance(&addr).map_err(ApiError::from)?;
        let all_utxos = storage.get_address_utxos(&addr).unwrap_or_default();
        let mut immature_count: usize = 0;
        let mut immature_value: u64 = 0;
        for (_, entry) in &all_utxos {
            if !entry.is_mature(chain_height) {
                immature_count += 1;
                immature_value += entry.value;
            }
        }
        let pending = {
            let mempool = self.mempool.lock();
            mempool.pending_debit_for_address(&addr)
        };
        let available = total_balance.saturating_sub(pending).saturating_sub(immature_value);

        // ── Transactions (same logic as getWalletTransactions, addresses_only mode) ──
        let addr_wire = addr.to_wire_bytes();
        let mut my_wires: Vec<Vec<u8>> = vec![addr_wire.clone()];

        // Add Hash160/Taproot variants for secp256k1 keys.
        if let NobleAddress::Noble(ref pk) = addr {
            if let Some(h160) = NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                my_wires.push(h160.to_wire_bytes());
            }
            if let Some(tap) = NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                my_wires.push(tap.to_wire_bytes());
            }
        }
        let is_ours = |wire: &[u8]| my_wires.iter().any(|w| w.as_slice() == wire);

        // Query address history.
        let mut all_addrs = vec![addr.clone()];
        if let NobleAddress::Noble(ref pk) = addr {
            if let Some(h160) = NobleAddress::bitcoin_hash160_for_pubkey(pk) {
                all_addrs.push(h160);
            }
            if let Some(tap) = NobleAddress::bitcoin_taproot_for_pubkey(pk) {
                all_addrs.push(tap);
            }
        }

        let mut seen = std::collections::HashSet::new();
        let mut all_tx_ids: Vec<(noble_crypto::Hash256, u64)> = Vec::new();
        for a in &all_addrs {
            let ids = match storage.get_address_history(a, 0, 1000) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(task = "wallet_snapshot", "address history lookup failed for {}: {e}", a.to_display_address());
                    continue;
                }
            };
            for id in ids {
                if !seen.insert(id) { continue; }
                match storage.get_transaction_location(&id) {
                    Ok((h, _)) => all_tx_ids.push((id, h)),
                    Err(e) => {
                        tracing::warn!(task = "wallet_snapshot", "tx location lookup failed for {}: {e}", hex::encode(id.as_bytes()));
                        continue;
                    }
                }
            }
        }
        all_tx_ids.sort_by(|a, b| b.1.cmp(&a.1));

        let mut entries = Vec::new();
        for (tx_id, height) in &all_tx_ids {
            let tx = match storage.get_transaction(tx_id) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(task = "wallet_snapshot", "failed to read tx {}: {e}", hex::encode(tx_id.as_bytes()));
                    continue;
                }
            };

            let tx_id_hex = hex::encode(tx_id.as_bytes());
            let confirmations = chain_height.saturating_sub(*height) + 1;
            let status = confirmation_status_label(Some(confirmations));

            let mut resp = tx_to_response(&tx, &tx_id_hex);
            resp.confirmations = Some(confirmations);
            resp.confirmation_status = Some(status.clone());

            if !tx.is_coinbase() {
                let mut input_total: u64 = 0;
                let mut all_resolved = true;
                for inp in &tx.inputs {
                    match storage.get_transaction(&inp.prev_output.txid) {
                        Ok(prev_tx) => {
                            if let Some(out) = prev_tx.outputs.get(inp.prev_output.vout as usize) {
                                input_total += out.value;
                            } else { all_resolved = false; }
                        }
                        Err(_) => { all_resolved = false; } // pruned UTXO — fee will be None
                    }
                }
                if all_resolved && input_total > 0 {
                    resp.fee = Some(input_total.saturating_sub(tx.total_output_value()));
                }
            }

            let is_sender = tx.issuer_sig.to_noble_public_key().ok()
                .map(|pk| is_ours(&NobleAddress::Noble(pk).to_wire_bytes()))
                .unwrap_or(false);

            let tx_type_names = [
                (0x00, "Notarization"), (0x01, "Transfer"), (0x02, "Key Rotation"),
                (0x03, "Badge Proposal"), (0x04, "Badge Vote"), (0x05, "Badge Revocation"),
                (0x06, "Locked"), (0x07, "Unlocking"), (0x10, "Block Reward"),
                (0x11, "Fee Distribution"),
            ];
            let type_label = tx_type_names.iter()
                .find(|(code, _)| *code == tx.tx_type)
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| format!("Type 0x{:02x}", tx.tx_type));

            let (direction, amount) = if tx.tx_type == 0x11 {
                let fee_income: u64 = tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value).sum();
                ("incoming".to_string(), fee_income)
            } else if tx.is_coinbase() {
                let reward: u64 = tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value).sum();
                ("incoming".to_string(), reward)
            } else if tx.tx_type == 0x01 {
                if is_sender {
                    let sent: u64 = tx.outputs.iter()
                        .filter(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value).sum();
                    ("outgoing".to_string(), sent)
                } else {
                    let received: u64 = tx.outputs.iter()
                        .filter(|o| is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value).sum();
                    ("incoming".to_string(), received)
                }
            } else if tx.tx_type == 0x00 || tx.tx_type == 0x06 || tx.tx_type == 0x07 {
                let fee_amount = resp.fee.unwrap_or(0);
                if is_sender {
                    ("outgoing".to_string(), fee_amount)
                } else {
                    ("incoming".to_string(), fee_amount)
                }
            } else if tx.tx_type == 0x02 {
                ("self".to_string(), 0)
            } else {
                ("self".to_string(), 0)
            };

            resp.direction = Some(direction);
            resp.amount = Some(amount);
            resp.type_label = Some(type_label);
            resp.block_height = Some(*height);
            resp.status = Some(status);
            entries.push(resp);
        }

        // Prepend pending mempool txs.
        let mut pending_entries = Vec::new();
        {
            let mempool = self.mempool.lock();
            for entry in mempool.iter_by_fee_rate_desc() {
                let issuer_wire = entry.tx.issuer_sig.to_noble_public_key().ok()
                    .map(|pk| NobleAddress::Noble(pk).to_wire_bytes());
                let sender_is_ours = issuer_wire.as_ref()
                    .map(|w| is_ours(w)).unwrap_or(false);
                let value_to_us: u64 = entry.tx.outputs.iter()
                    .filter(|o| is_ours(&o.address.to_wire_bytes()))
                    .map(|o| o.value).sum();
                if !sender_is_ours && value_to_us == 0 { continue; }

                let (dir, amt) = if sender_is_ours {
                    let sent: u64 = entry.tx.outputs.iter()
                        .filter(|o| !is_ours(&o.address.to_wire_bytes()))
                        .map(|o| o.value).sum();
                    ("outgoing", sent)
                } else {
                    ("incoming", value_to_us)
                };

                let type_label = [
                    (0x00, "Notarization"), (0x01, "Transfer"), (0x02, "Key Rotation"),
                    (0x03, "Badge Proposal"), (0x04, "Badge Vote"), (0x05, "Badge Revocation"),
                    (0x06, "Locked"), (0x07, "Unlocking"), (0x10, "Block Reward"),
                    (0x11, "Fee Distribution"),
                ].iter()
                    .find(|(code, _)| *code == entry.tx.tx_type)
                    .map(|(_, name)| format!("Pending {name}"))
                    .unwrap_or_else(|| "Pending".to_string());

                let tx_id_hex = hex::encode(entry.tx_id.as_bytes());
                let mut resp = tx_to_response(&entry.tx, &tx_id_hex);
                resp.fee = Some(entry.fee);
                resp.confirmation_status = Some("pending".to_string());
                resp.confirmations = Some(0);
                resp.direction = Some(dir.to_string());
                resp.amount = Some(amt);
                resp.type_label = Some(type_label);
                resp.block_height = None;
                resp.status = Some("pending".to_string());
                pending_entries.push(resp);
            }
        }

        pending_entries.extend(entries);

        Ok(WalletSnapshotResponse {
            chain_height,
            balance: total_balance,
            available,
            pending,
            immature_count,
            immature_value,
            transactions: pending_entries,
        })
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
