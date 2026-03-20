// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent faucet wallet — generates, stores, and signs transfers locally.
//!
//! The faucet maintains its own keystore (separate from the node's) so it can
//! build and sign transfer transactions without delegating to `walletSendTransfer`.

use noble_crypto::keys::NoblePublicKey;
use noble_crypto::SCHEME_SECP256K1;
use noble_wallet::builder::{SelectedUtxo, TransactionBuilder};
use noble_wallet::KeyStore;

use crate::rpc_client::NodeRpcClient;

/// A self-contained faucet wallet backed by a local keystore directory.
pub struct FaucetWallet {
    keystore: KeyStore,
    signer: NoblePublicKey,
    chain_id: u32,
}

impl FaucetWallet {
    /// Open (or create) a faucet wallet.
    ///
    /// `keystore_path` should point to a `.noble` file (new format).
    /// If the path is a directory (old format), it will be migrated.
    /// - If the keystore is empty, generates a new secp256k1 key.
    /// - Unlocks the keystore with `passphrase`.
    pub fn open_or_create(
        keystore_path: &std::path::Path,
        passphrase: &str,
        chain_id: u32,
    ) -> Result<Self, String> {
        // Generate a faucet-specific chain_meta from the passphrase (deterministic).
        let faucet_meta: [u8; 32] = *noble_crypto::sha256(passphrase.as_bytes()).as_bytes();
        let derived_pass = hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&faucet_meta));

        let ks_file = if keystore_path.is_dir() {
            // Legacy directory path — use file inside parent
            keystore_path.with_extension("noble")
        } else {
            keystore_path.to_path_buf()
        };

        let mut keystore = if KeyStore::exists(&ks_file) {
            KeyStore::open(&ks_file, &faucet_meta)
                .map_err(|e| format!("keystore open: {e}"))?
        } else if keystore_path.is_dir() {
            KeyStore::migrate_from_directory(keystore_path, &ks_file, &faucet_meta, &derived_pass)
                .map_err(|e| format!("keystore migrate: {e}"))?
        } else {
            KeyStore::create_for_faucet(&ks_file, &faucet_meta)
                .map_err(|e| format!("keystore create: {e}"))?
        };

        // Unlock with chain_meta-derived passphrase
        keystore.unlock(&derived_pass)
            .map_err(|e| format!("unlock: {e}"))?;

        // Check if we already have a key.
        let keys = keystore
            .list_keys()
            .map_err(|e| format!("list keys: {e}"))?;
        let signer = if let Some(pk) = keys.into_iter().next() {
            pk
        } else {
            // Generate new secp256k1 key
            keystore
                .create_key(SCHEME_SECP256K1, &derived_pass)
                .map_err(|e| format!("create key: {e}"))?
        };

        tracing::info!(
            "Faucet wallet ready: {}",
            signer.to_address()
        );

        Ok(Self { keystore, signer, chain_id })
    }

    /// Return the human-readable Noble address (nbl1…).
    pub fn address(&self) -> String {
        self.signer.to_address()
    }

    /// Build a signed transfer transaction and return its hex-encoded CBOR.
    ///
    /// Queries the node for available UTXOs via `getAddressUtxos` RPC,
    /// selects enough to cover `amount + fee`, and creates a proper
    /// UTXO-model transfer with change output.
    pub async fn build_transfer(
        &self,
        rpc: &NodeRpcClient,
        recipient_hex: &str,
        amount: u64,
        fee: u64,
        chain_height: u64,
    ) -> Result<String, String> {
        let recipient = noble_core::NobleAddress::from_wire_bytes(
            &hex::decode(recipient_hex).map_err(|e| format!("bad recipient hex: {e}"))?,
        )
        .map_err(|e| format!("bad recipient: {e}"))?;

        let change_address =
            noble_core::NobleAddress::Noble(self.signer.clone());

        // Query real UTXOs from the node
        let utxos = rpc.get_address_utxos(&self.address()).await
            .map_err(|e| format!("get UTXOs: {e}"))?;

        if utxos.is_empty() {
            return Err("faucet has no UTXOs (dry)".into());
        }

        // Select UTXOs (largest-first) until we have enough
        let required = amount.saturating_add(fee);
        let mut selected = Vec::new();
        let mut total = 0u64;
        // Filter out immature coinbase UTXOs, then sort by value descending
        let mut sorted: Vec<_> = utxos.into_iter().filter(|u| {
            !u.is_coinbase || chain_height >= u.height + noble_core::COINBASE_MATURITY
        }).collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

        if sorted.is_empty() {
            return Err("faucet has no mature UTXOs (all coinbase UTXOs are immature)".into());
        }

        for utxo in &sorted {
            selected.push(SelectedUtxo {
                outpoint: noble_core::OutPoint {
                    txid: noble_crypto::Hash256::from_hex(&utxo.txid)
                        .map_err(|e| format!("bad utxo txid {}: {e}", utxo.txid))?,
                    vout: utxo.vout,
                },
                value: utxo.value,
            });
            total = total.saturating_add(utxo.value);
            if total >= required {
                break;
            }
        }

        if total < required {
            return Err(format!(
                "insufficient UTXOs: have {total}, need {required}"
            ));
        }

        let tx = TransactionBuilder::build_transfer(
            &self.keystore,
            &self.signer,
            recipient,
            amount,
            fee,
            None,
            self.chain_id,
            &selected,
            &change_address,
        )
        .map_err(|e| format!("build transfer: {e}"))?;

        let cbor = noble_tx_core::encode_transaction(&tx)
            .map_err(|e| format!("C encoder: {e}"))?;
        Ok(hex::encode(cbor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_wallet_create_and_address() {
        let dir = tempfile::tempdir().unwrap();
        let ks_path = dir.path().join("faucet.noble");
        let w = FaucetWallet::open_or_create(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
        let addr = w.address();
        // secp256k1: nbl1p… bech32m address
        assert!(addr.starts_with("nbl1p"), "should be Noble secp256k1 address (nbl1p…), got: {addr}");
        // Verify roundtrip
        let decoded = noble_crypto::noble_addr::decode(&addr).unwrap();
        assert_eq!(decoded.scheme_id(), noble_crypto::SCHEME_SECP256K1);
    }

    #[test]
    fn faucet_wallet_reopen_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let ks_path = dir.path().join("faucet.noble");
        let w1 = FaucetWallet::open_or_create(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
        let addr1 = w1.address();
        drop(w1);

        let w2 = FaucetWallet::open_or_create(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
        assert_eq!(w2.address(), addr1, "same keystore should yield same address");
    }
}
