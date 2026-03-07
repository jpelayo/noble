// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent faucet wallet — generates, stores, and signs transfers locally.
//!
//! The faucet maintains its own keystore (separate from the node's) so it can
//! build and sign transfer transactions without delegating to `walletSendTransfer`.

use noble_codec::NobleCbor;
use noble_crypto::keys::NoblePublicKey;
use noble_crypto::SCHEME_ED25519;
use noble_wallet::builder::TransactionBuilder;
use noble_wallet::KeyStore;

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
        let _ = keystore.unlock(passphrase);

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
    /// The returned string can be submitted via `noble_submitTransaction`.
    pub fn build_transfer(
        &self,
        recipient_hex: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String, String> {
        let recipient = noble_core::NobleAddress::from_wire_bytes(
            &hex::decode(recipient_hex).map_err(|e| format!("bad recipient hex: {e}"))?,
        )
        .map_err(|e| format!("bad recipient: {e}"))?;

        let tx = TransactionBuilder::build_transfer(
            &self.keystore,
            &self.signer,
            recipient,
            amount,
            fee,
            None,
            None,
            self.chain_id,
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
