// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent faucet wallet — uses the same noble-tx-core C library
//! as all client apps for coin selection, fee computation, signing, and encoding.

use noble_crypto::keys::NoblePublicKey;
use noble_crypto::SCHEME_SECP256K1;
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

    /// Build a signed transfer using the same noble-tx-core C library the client apps use.
    ///
    /// Uses the same noble-tx-core C library functions as Swift/WRY clients:
    /// 1. `noble_select_utxos` — 5-pass coin selection
    /// 2. `noble_sign_transfer` — two-pass fee computation + signing + CBOR encoding
    pub async fn build_transfer(
        &self,
        rpc: &NodeRpcClient,
        recipient_hex: &str,
        amount: u64,
        fee_rate: u64,
    ) -> Result<String, String> {
        // Get private key from keystore (secp256k1 = scheme 0x02)
        let private_key = self.keystore
            .get_raw(noble_crypto::SCHEME_SECP256K1)
            .map_err(|e| format!("load private key: {e}"))?;
        let private_key_hex = hex::encode(&private_key);

        // Change address = faucet's own address (wire hex)
        let change_hex = hex::encode(self.signer.to_wire_bytes());

        // Query available UTXOs from the node — server computes maturity and pending status.
        let utxos = rpc.get_address_utxos(&self.address()).await
            .map_err(|e| format!("get UTXOs: {e}"))?;

        if utxos.is_empty() {
            return Err("faucet has no UTXOs (dry)".into());
        }

        // Filter to available only — same as client apps.
        let available: Vec<_> = utxos.into_iter().filter(|u| {
            match u.status.as_deref() {
                Some("available") | None => true,
                _ => false,
            }
        }).collect();

        if available.is_empty() {
            return Err("faucet has no spendable UTXOs (all are immature, pending, or locked by other transactions)".into());
        }

        // Build UTXO JSON array
        let all_utxo_json: Vec<serde_json::Value> = available.iter().map(|u| {
            serde_json::json!({
                "txid": u.txid,
                "vout": u.vout,
                "value": u.value,
            })
        }).collect();

        // 5-pass coin selection — same algorithm the Swift/WRY clients use.
        // Selects the optimal subset of UTXOs for the target amount.
        let target = amount.saturating_add(fee_rate.saturating_mul(500)); // generous estimate for selection
        let select_params = serde_json::json!({
            "target": target,
            "utxos": all_utxo_json,
        });
        let select_result = noble_tx_core::select_utxos(&select_params.to_string())
            .map_err(|e| format!("coin selection: {e}"))?;
        let select_json: serde_json::Value = serde_json::from_str(&select_result)
            .map_err(|e| format!("parse selection: {e}"))?;
        if let Some(err) = select_json.get("error").and_then(|v| v.as_str()) {
            return Err(format!("coin selection: {err}"));
        }
        let utxo_json = select_json.get("selected")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or(all_utxo_json);

        // Build params JSON — same structure the Swift/WRY clients pass to noble_sign_transfer
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let params = serde_json::json!({
            "recipient": recipient_hex,
            "amount": amount,
            "fee": 0,
            "fee_rate": fee_rate,
            "utxos": utxo_json,
            "change_address": change_hex,
            "private_key": private_key_hex,
            "chain_id": self.chain_id,
            "timestamp": now,
        });

        // Call the same C library function all clients use
        let result_json = noble_tx_core::sign_transfer(&params.to_string())
            .map_err(|e| format!("sign_transfer: {e}"))?;

        // Parse result — the C library returns {"tx_hex": "..."} or {"error": "..."}
        let result: serde_json::Value = serde_json::from_str(&result_json)
            .map_err(|e| format!("parse result: {e}"))?;

        if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
            return Err(format!("sign_transfer: {err}"));
        }

        result.get("tx_hex")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "sign_transfer: missing tx_hex in result".to_string())
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
