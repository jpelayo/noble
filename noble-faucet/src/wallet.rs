// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Independent faucet wallet — uses the same noble-tx-core C library
//! as all client apps for coin selection, fee computation, signing, and encoding.

use noble_crypto::keys::{NoblePrivateKey, NoblePublicKey};
use noble_wallet::KeyStore;

use crate::rpc_client::NodeRpcClient;

/// Why `FaucetWallet::open` could not produce a wallet. `Missing`/`NoKey` are
/// the ONLY states in which creating a wallet is permissible — `Other`
/// (corrupt file, wrong passphrase, I/O) must never be "fixed" by creation.
#[derive(Debug)]
pub enum OpenError {
    /// No keystore file exists at the resolved path.
    Missing(std::path::PathBuf),
    /// The keystore exists and opens, but holds no key (crashed creation).
    NoKey(std::path::PathBuf),
    /// Any other failure — corrupt keystore, wrong passphrase, I/O.
    Other(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(p) => write!(f, "faucet keystore not found at {}", p.display()),
            Self::NoKey(p) => write!(f, "faucet keystore at {} contains no key", p.display()),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

/// A self-contained faucet wallet backed by a local keystore directory.
pub struct FaucetWallet {
    keystore: KeyStore,
    signer: NoblePublicKey,
    chain_id: u32,
}

impl FaucetWallet {
    /// Resolve the keystore FILE from a configured path (legacy directory
    /// configs map to a `.noble` sibling).
    pub fn keystore_file(keystore_path: &std::path::Path) -> std::path::PathBuf {
        if keystore_path.is_dir() {
            keystore_path.with_extension("noble")
        } else {
            keystore_path.to_path_buf()
        }
    }

    /// Faucet-specific chain_meta + wallet passphrase, both deterministic
    /// from the operator passphrase (which lives durably in the NODE
    /// keystore). Encryption only — the KEY derivation is `derive_secret`.
    fn meta_and_pass(passphrase: &str) -> ([u8; 32], String) {
        let faucet_meta: [u8; 32] = *noble_crypto::sha256(passphrase.as_bytes()).as_bytes();
        let derived_pass =
            hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&faucet_meta));
        (faucet_meta, derived_pass)
    }

    /// Derive the faucet's secp256k1 secret deterministically from the
    /// passphrase (domain-tagged). Same passphrase ⇒ same key ⇒ same address,
    /// forever — the keystore file is a CACHE, not the sole custody of the
    /// key. Retries with a counter byte in the astronomically-unlikely
    /// (~2⁻¹²⁸) event the hash is not a valid scalar.
    fn derive_secret(passphrase: &str) -> Result<[u8; 32], String> {
        for counter in 0u8..=255 {
            let mut input = b"noble-faucet-wallet-v1".to_vec();
            input.extend_from_slice(passphrase.as_bytes());
            if counter > 0 {
                input.push(counter);
            }
            let secret: [u8; 32] = *noble_crypto::sha256(&input).as_bytes();
            if noble_crypto::secp256k1::keypair_from_secret(&secret).is_ok() {
                return Ok(secret);
            }
        }
        Err("could not derive a valid secp256k1 secret from the passphrase".into())
    }

    /// The address this passphrase WOULD derive — for refusal diagnostics,
    /// without touching any keystore.
    pub fn derived_address(passphrase: &str) -> Result<String, String> {
        let secret = Self::derive_secret(passphrase)?;
        let (sk, _pk) = noble_crypto::secp256k1::keypair_from_secret(&secret)
            .map_err(|e| format!("derive keypair: {e}"))?;
        Ok(NoblePrivateKey::Secp256k1(sk).public_key().to_address())
    }

    /// Open an EXISTING faucet wallet. Errors if the keystore file is missing
    /// (`OpenError::Missing`) or holds no key (`OpenError::NoKey`) — this
    /// function NEVER creates anything. Custody rule: wallet creation is an
    /// explicit act (`create_derived`, gated by the caller), never a side
    /// effect of a missing file. A missing file silently re-minting the
    /// faucet identity is how funds were stranded three times before.
    pub fn open(
        keystore_path: &std::path::Path,
        passphrase: &str,
        chain_id: u32,
    ) -> Result<Self, OpenError> {
        let (faucet_meta, derived_pass) = Self::meta_and_pass(passphrase);
        let ks_file = Self::keystore_file(keystore_path);

        let mut keystore = if KeyStore::exists(&ks_file) {
            KeyStore::open(&ks_file, &faucet_meta)
                .map_err(|e| OpenError::Other(format!("keystore open: {e}")))?
        } else if keystore_path.is_dir() {
            // Legacy directory-based keystore — migrate in place.
            KeyStore::migrate_from_directory(keystore_path, &ks_file, &faucet_meta, &derived_pass)
                .map_err(|e| OpenError::Other(format!("keystore migrate: {e}")))?
        } else {
            return Err(OpenError::Missing(ks_file));
        };

        keystore
            .unlock(&derived_pass)
            .map_err(|e| OpenError::Other(format!("unlock: {e}")))?;

        let keys = keystore
            .list_keys()
            .map_err(|e| OpenError::Other(format!("list keys: {e}")))?;
        let signer = keys
            .into_iter()
            .next()
            .ok_or(OpenError::NoKey(ks_file))?;

        tracing::info!("Faucet wallet ready: {}", signer.to_address());
        Ok(Self { keystore, signer, chain_id })
    }

    /// Create a NEW faucet wallet whose key is DERIVED from the passphrase
    /// (`derive_secret`). Recoverable by construction: as long as the node
    /// keystore (holding the passphrase) survives, recreating after keystore
    /// loss yields the SAME address. Accepts an existing-but-keyless keystore
    /// (crashed prior creation); errors if a key already exists (use `open`).
    pub fn create_derived(
        keystore_path: &std::path::Path,
        passphrase: &str,
        chain_id: u32,
    ) -> Result<Self, String> {
        let (faucet_meta, derived_pass) = Self::meta_and_pass(passphrase);
        let ks_file = Self::keystore_file(keystore_path);

        let mut keystore = if KeyStore::exists(&ks_file) {
            KeyStore::open(&ks_file, &faucet_meta)
                .map_err(|e| format!("keystore open: {e}"))?
        } else {
            KeyStore::create_for_faucet(&ks_file, &faucet_meta)
                .map_err(|e| format!("keystore create: {e}"))?
        };

        keystore
            .unlock(&derived_pass)
            .map_err(|e| format!("unlock: {e}"))?;

        if !keystore
            .list_keys()
            .map_err(|e| format!("list keys: {e}"))?
            .is_empty()
        {
            return Err(format!(
                "faucet keystore at {} already holds a key — use open()",
                ks_file.display()
            ));
        }

        let secret = Self::derive_secret(passphrase)?;
        let signer = keystore
            .import_secp256k1_key(&hex::encode(secret), &derived_pass)
            .map_err(|e| format!("import derived key: {e}"))?;

        tracing::info!(
            "Faucet wallet created (passphrase-derived, recoverable): {}",
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

        // Split faucet amount into multiple UTXOs so the recipient can do batch operations.
        // Each UTXO is sized at 4× typical notarization fee. Capped at 64 outputs.
        let typical_notarization_fee = fee_rate.saturating_mul(200); // ~200 bytes typical
        let min_utxo_value = typical_notarization_fee.saturating_mul(4);
        let split_count = if min_utxo_value > 0 {
            (amount / min_utxo_value).min(63).max(1) as usize  // 63 max (leave 1 slot for change)
        } else {
            1
        };
        let per_output = amount / split_count as u64;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let result_json = if split_count > 1 {
            // Multi-output: N outputs to recipient, each of per_output value
            let outputs: Vec<serde_json::Value> = (0..split_count).map(|i| {
                let val = if i == split_count - 1 {
                    // Last output gets remainder to avoid rounding loss
                    amount - per_output * (split_count as u64 - 1)
                } else {
                    per_output
                };
                serde_json::json!({ "address": recipient_hex, "amount": val })
            }).collect();
            let params = serde_json::json!({
                "outputs": outputs,
                "fee": 0,
                "fee_rate": fee_rate,
                "utxos": utxo_json,
                "change_address": change_hex,
                "private_key": private_key_hex,
                "chain_id": self.chain_id,
                "timestamp": now,
            });
            tracing::info!(task = "faucet", "splitting faucet send into {} UTXOs of ~{} groats each", split_count, per_output);
            noble_tx_core::sign_split_transfer(&params.to_string())
                .map_err(|e| format!("sign_split_transfer: {e}"))?
        } else {
            // Single output: standard transfer
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
            noble_tx_core::sign_transfer(&params.to_string())
                .map_err(|e| format!("sign_transfer: {e}"))?
        };

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
        let w = FaucetWallet::create_derived(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
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
        let w1 = FaucetWallet::create_derived(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
        let addr1 = w1.address();
        drop(w1);

        let w2 = FaucetWallet::open(&ks_path, "test-pass-long", 0x4E4F424C).unwrap();
        assert_eq!(w2.address(), addr1, "same keystore should yield same address");
    }

    #[test]
    fn open_never_creates() {
        let dir = tempfile::tempdir().unwrap();
        let ks_path = dir.path().join("faucet.noble");
        match FaucetWallet::open(&ks_path, "test-pass-long", 0x4E4F424C) {
            Err(OpenError::Missing(p)) => assert_eq!(p, ks_path),
            Err(e) => panic!("expected Missing, got {e:?}"),
            Ok(_) => panic!("expected Missing, got a wallet"),
        }
        // The custody rule in one assertion: open() must leave NO file behind.
        assert!(!ks_path.exists(), "open() must never create a keystore");
    }

    #[test]
    fn derived_key_is_deterministic_and_passphrase_bound() {
        // Same passphrase in two fresh keystores → SAME address.
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let a1 = FaucetWallet::create_derived(&d1.path().join("a.noble"), "pass-one-long", 1)
            .unwrap()
            .address();
        let a2 = FaucetWallet::create_derived(&d2.path().join("b.noble"), "pass-one-long", 1)
            .unwrap()
            .address();
        assert_eq!(a1, a2, "same passphrase must derive the same address");

        // Different passphrase → different address.
        let d3 = tempfile::tempdir().unwrap();
        let a3 = FaucetWallet::create_derived(&d3.path().join("c.noble"), "pass-two-long", 1)
            .unwrap()
            .address();
        assert_ne!(a1, a3, "different passphrase must derive a different address");

        // derived_address() (diagnostics path) agrees with actual creation.
        assert_eq!(FaucetWallet::derived_address("pass-one-long").unwrap(), a1);
    }

    #[test]
    fn keystore_loss_is_recoverable() {
        // THE property this whole fix exists for: losing the keystore file is
        // a non-event — recreation from the same passphrase restores the SAME
        // address (and therefore access to the same on-chain funds).
        let dir = tempfile::tempdir().unwrap();
        let ks_path = dir.path().join("faucet.noble");
        let addr1 = FaucetWallet::create_derived(&ks_path, "durable-pass", 1)
            .unwrap()
            .address();
        std::fs::remove_file(&ks_path).unwrap(); // simulate the historic loss
        let addr2 = FaucetWallet::create_derived(&ks_path, "durable-pass", 1)
            .unwrap()
            .address();
        assert_eq!(addr1, addr2, "recreation after keystore loss must restore the same address");
    }

    #[test]
    fn create_refuses_when_key_exists() {
        let dir = tempfile::tempdir().unwrap();
        let ks_path = dir.path().join("faucet.noble");
        FaucetWallet::create_derived(&ks_path, "test-pass-long", 1).unwrap();
        let err = match FaucetWallet::create_derived(&ks_path, "test-pass-long", 1) {
            Ok(_) => panic!("second create_derived must fail"),
            Err(e) => e,
        };
        assert!(err.contains("already holds a key"), "got: {err}");
    }
}
