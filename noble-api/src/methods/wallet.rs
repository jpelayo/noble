// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet-related RPC methods: createAddress, walletUnlock, walletLock,
//! getWalletInfo, walletSendTransfer, submitDocumentBatch.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_core::MIN_TX_FEE;
use noble_crypto::{sha256, Hash256, NoblePublicKey, SCHEME_ED25519 as SCHEME_ED, SCHEME_SECP256K1 as SCHEME_SEC};
use noble_mempool::{BalanceLookup, ChainLookup};
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;
use noble_wallet::TransactionBuilder;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

// ---------------------------------------------------------------------------
// Adapter structs (same as transaction.rs — duplicated to avoid module coupling)
// ---------------------------------------------------------------------------

struct StorageChainLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> ChainLookup for StorageChainLookup<'_, S> {
    fn is_confirmed(&self, tx_id: &Hash256) -> bool {
        self.storage.has_transaction(tx_id).unwrap_or(false)
    }
}

struct StorageBalanceLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> BalanceLookup for StorageBalanceLookup<'_, S> {
    fn get_balance(&self, pubkey: &NoblePublicKey) -> u64 {
        self.storage.get_balance(pubkey).unwrap_or(0)
    }
}

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
    #[method(name = "walletSendTransfer")]
    async fn wallet_send_transfer(
        &self,
        from: String,
        to: String,
        amount: u64,
        fee: Option<u64>,
        memo: Option<String>,
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

    /// List all public keys in the wallet keystore.
    ///
    /// Does not require the wallet to be unlocked — reads key filenames only.
    #[method(name = "listAddresses")]
    async fn list_addresses(&self) -> Result<ListAddressesResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> WalletApiServer for Arc<ApiState<S>> {
    async fn create_address(
        &self,
        scheme_id: u8,
        passphrase: String,
    ) -> Result<CreateAddressResponse, ErrorObjectOwned> {
        let mut keystore = self.wallet_keystore.lock();
        let pubkey = keystore
            .create_key(scheme_id, &passphrase)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(CreateAddressResponse {
            address: hex::encode(pubkey.to_wire_bytes()),
            scheme_id: pubkey.scheme_id(),
        })
    }

    async fn wallet_unlock(
        &self,
        passphrase: String,
        timeout_secs: u64,
    ) -> Result<WalletUnlockResponse, ErrorObjectOwned> {
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

        let keys = keystore.list_keys().unwrap_or_default();
        let key_count = keys.len();

        // Sum balances across all wallet keys
        let storage = self.storage.read();
        let mempool = self.mempool.lock();
        let mut total_balance = 0u64;
        let mut total_pending = 0u64;
        for pk in &keys {
            total_balance += storage.get_balance(pk).unwrap_or(0);
            total_pending += mempool.pending_debit(pk);
        }
        drop(mempool);
        drop(storage);

        Ok(WalletInfoResponse {
            unlocked: state.is_unlocked(),
            expires_at: state.expires_at_unix(),
            key_count,
            balance: total_balance,
            available: total_balance.saturating_sub(total_pending),
            pending: total_pending,
        })
    }

    async fn wallet_send_transfer(
        &self,
        from: String,
        to: String,
        amount: u64,
        fee: Option<u64>,
        memo: Option<String>,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // Ensure wallet is unlocked
        {
            let state = self.wallet_state.lock();
            if !state.is_unlocked() {
                return Err(ApiError::WalletLocked.into());
            }
        }

        // Validate amount > 0
        if amount == 0 {
            return Err(ApiError::InvalidParam("transfer amount must be > 0".into()).into());
        }

        // Parse addresses
        let sender = parse_pubkey(&from)?;
        let recipient = parse_pubkey(&to)?;

        let fee = fee.unwrap_or(MIN_TX_FEE);

        // Build and sign the transaction (inject gateway address if configured)
        let tx = {
            let keystore = self.wallet_keystore.lock();
            let mut tx = TransactionBuilder::build_transfer(
                &keystore, &sender, recipient, amount, fee, memo,
            )
            .map_err(|e| match e {
                noble_wallet::WalletError::Locked => ApiError::WalletLocked,
                noble_wallet::WalletError::InsufficientBalance { have, need } => {
                    ApiError::InsufficientBalance(format!("have {have}, need {need}"))
                }
                other => ApiError::Internal(other.to_string()),
            })?;
            {
                let gw_guard = self.gateway_key.read();
                if let Some(ref gw) = *gw_guard {
                    TransactionBuilder::set_gateway_and_resign(
                        &mut tx,
                        &keystore,
                        &sender,
                        gw.clone(),
                    )
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                }
            }
            tx
        };

        // Admit to mempool
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tx_id = {
            let storage = self.storage.read();
            let chain_lookup = StorageChainLookup { storage: &*storage };
            let balance_lookup = StorageBalanceLookup { storage: &*storage };
            let mut mempool = self.mempool.lock();
            mempool
                .admit(&tx, now, &chain_lookup, &balance_lookup)
                .map_err(|e| ApiError::TxRejected(e.to_string()))?
        };

        // Broadcast (log if channel full).
        if let Err(e) = self
            .network_cmd
            .try_send(NetworkCommand::PublishTransaction(tx))
        {
            tracing::warn!(task = "tx_broadcast", %tx_id, "network broadcast dropped (channel full): {e}");
        }

        Ok(SubmitTxResponse {
            tx_id: hash_to_hex(&tx_id),
            accepted: true,
        })
    }

    async fn generate_mnemonic(
        &self,
        word_count: Option<u32>,
        passphrase: String,
    ) -> Result<GenerateMnemonicResponse, ErrorObjectOwned> {
        let wc = word_count.unwrap_or(24) as usize;
        if wc != 12 && wc != 24 {
            return Err(ApiError::InvalidParam("word_count must be 12 or 24".into()).into());
        }

        let mut keystore = self.wallet_keystore.lock();
        let (mnemonic, pubkey) = keystore
            .create_key_from_mnemonic(wc, &passphrase)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(GenerateMnemonicResponse {
            mnemonic,
            address: hex::encode(pubkey.to_wire_bytes()),
            scheme_id: pubkey.scheme_id(),
            word_count: wc,
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
                    SCHEME_ED => "ed25519",
                    SCHEME_SEC => "secp256k1",
                    _ => "unknown",
                };
                WalletKeyEntry {
                    pubkey_hex: hex::encode(pk.to_wire_bytes()),
                    scheme: scheme.to_string(),
                }
            })
            .collect();
        Ok(ListAddressesResponse { keys: entries })
    }

    async fn import_mnemonic(
        &self,
        mnemonic: String,
        passphrase: String,
    ) -> Result<ImportMnemonicResponse, ErrorObjectOwned> {
        let mut keystore = self.wallet_keystore.lock();

        // Check if key already exists by trying to recover
        let existing_keys: Vec<_> = keystore.list_keys().unwrap_or_default();
        let pubkey = keystore
            .recover_from_mnemonic(&mnemonic, &passphrase)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let already_exists = existing_keys
            .iter()
            .any(|k| k.to_wire_bytes() == pubkey.to_wire_bytes());

        Ok(ImportMnemonicResponse {
            address: hex::encode(pubkey.to_wire_bytes()),
            scheme_id: pubkey.scheme_id(),
            already_exists,
        })
    }

    async fn submit_document_batch(
        &self,
        signer: String,
        checksums: Vec<String>,
        fee_per_tx: Option<u64>,
    ) -> Result<SubmitBatchResponse, ErrorObjectOwned> {
        // Limit to 100 checksums
        if checksums.len() > 100 {
            return Err(ApiError::TxRejected("batch limited to 100 checksums".into()).into());
        }

        // Ensure wallet is unlocked
        {
            let state = self.wallet_state.lock();
            if !state.is_unlocked() {
                return Err(ApiError::WalletLocked.into());
            }
        }

        // Parse signer address
        let signer_pk = parse_pubkey(&signer)?;

        let fee = fee_per_tx.unwrap_or(MIN_TX_FEE);
        let mut results = Vec::with_capacity(checksums.len());
        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for checksum_hex in &checksums {
            let entry = match self.process_single_notarization(&signer_pk, checksum_hex, fee) {
                Ok((tx_id_hex, _checksum_display)) => {
                    accepted += 1;
                    BatchResultEntry {
                        checksum: checksum_hex.clone(),
                        tx_id: Some(tx_id_hex),
                        error: None,
                    }
                }
                Err(err_msg) => {
                    rejected += 1;
                    BatchResultEntry {
                        checksum: checksum_hex.clone(),
                        tx_id: None,
                        error: Some(err_msg),
                    }
                }
            };
            results.push(entry);
        }

        Ok(SubmitBatchResponse {
            results,
            accepted,
            rejected,
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers on ApiState
// ---------------------------------------------------------------------------

impl<S: StorageEngine + Send + Sync + 'static> ApiState<S> {
    /// Process a single notarization in a batch. Returns `Ok((tx_id_hex, checksum_hex))`
    /// or `Err(error_message)`.
    fn process_single_notarization(
        self: &Arc<Self>,
        signer: &NoblePublicKey,
        checksum_hex: &str,
        fee: u64,
    ) -> Result<(String, String), String> {
        // Parse checksum: if it's 64 hex chars, treat as raw hash; otherwise hash the input.
        let checksum = if checksum_hex.len() == 64 {
            let bytes = hex::decode(checksum_hex).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            Hash256::from_bytes(arr)
        } else {
            // Hash the hex string as document content identifier
            sha256(checksum_hex.as_bytes())
        };

        // Build transaction (inject gateway address if configured)
        let tx = {
            let keystore = self.wallet_keystore.lock();
            let mut tx = TransactionBuilder::build_notarization(
                &keystore,
                signer,
                checksum,
                fee,
                vec![], // no metadata in batch mode
            )
            .map_err(|e| e.to_string())?;
            {
                let gw_guard = self.gateway_key.read();
                if let Some(ref gw) = *gw_guard {
                    TransactionBuilder::set_gateway_and_resign(
                        &mut tx,
                        &keystore,
                        signer,
                        gw.clone(),
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            tx
        };

        // Admit to mempool
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tx_id = {
            let storage = self.storage.read();
            let chain_lookup = StorageChainLookup { storage: &*storage };
            let balance_lookup = StorageBalanceLookup { storage: &*storage };
            let mut mempool = self.mempool.lock();
            mempool
                .admit(&tx, now, &chain_lookup, &balance_lookup)
                .map_err(|e| e.to_string())?
        };

        // Broadcast (log if channel full).
        if let Err(e) = self
            .network_cmd
            .try_send(NetworkCommand::PublishTransaction(tx))
        {
            tracing::warn!(task = "tx_broadcast", %tx_id, "network broadcast dropped (channel full): {e}");
        }

        Ok((hash_to_hex(&tx_id), hash_to_hex(&checksum)))
    }
}
