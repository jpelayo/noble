// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent faucet wallet — generates, stores, and signs transfers locally.
//!
//! The faucet maintains its own keystore (separate from the node's) so it can
//! build and sign transfer transactions without delegating to `walletSendTransfer`.

use noble_codec::NobleCbor;
use noble_crypto::keys::NoblePublicKey;
use noble_crypto::SCHEME_ED25519;
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
    /// Open (or create) a faucet wallet in `keystore_dir`.
    ///
    /// - If the keystore is empty, generates a new Ed25519 key.
    /// - Unlocks the keystore with `passphrase`.
    pub fn open_or_create(
        keystore_dir: &std::path::Path,
        passphrase: &str,
        chain_id: u32,
    ) -> Result<Self, String> {
        let mut keystore =
            KeyStore::new(keystore_dir).map_err(|e| format!("keystore init: {e}"))?;

        // Try unlock first (may already have keys).
        if let Err(e) = keystore.unlock(passphrase) {
            tracing::debug!("initial unlock attempt: {e}");
        }

        // Check if we already have a key.
        let keys = keystore
            .list_keys()
            .map_err(|e| format!("list keys: {e}"))?;
        let signer = if let Some(pk) = keys.into_iter().next() {
            pk
        } else {
            // Generate new Ed25519 key
            keystore
                .create_key(SCHEME_ED25519, passphrase)
                .map_err(|e| format!("create key: {e}"))?
        };

        // Ensure unlocked
        if !keystore.is_unlocked() {
            keystore
                .unlock(passphrase)
                .map_err(|e| format!("unlock: {e}"))?;
        }

        tracing::info!(
            "Faucet wallet ready: {}",
            hex::encode(signer.to_wire_bytes())
        );

        Ok(Self { keystore, signer, chain_id })
    }

    /// Return the hex-encoded wire public key (used as the faucet address).
    pub fn address(&self) -> String {
        hex::encode(self.signer.to_wire_bytes())
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

        let cbor = tx.to_cbor().map_err(|e| format!("cbor encode: {e}"))?;
        Ok(hex::encode(cbor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_wallet_create_and_address() {
        let dir = tempfile::tempdir().unwrap();
        let w = FaucetWallet::open_or_create(dir.path(), "test-pass-long", 0x4E4F424C).unwrap();
        let addr = w.address();
        // Ed25519: 1 byte scheme + 32 bytes key = 33 bytes = 66 hex chars
        assert_eq!(addr.len(), 66, "address should be 66 hex chars");
        assert!(addr.starts_with("01"), "should be Ed25519 scheme prefix");
    }

    #[test]
    fn faucet_wallet_reopen_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let w1 = FaucetWallet::open_or_create(dir.path(), "test-pass-long", 0x4E4F424C).unwrap();
        let addr1 = w1.address();
        drop(w1);

        let w2 = FaucetWallet::open_or_create(dir.path(), "test-pass-long", 0x4E4F424C).unwrap();
        assert_eq!(w2.address(), addr1, "same keystore should yield same address");
    }
}
