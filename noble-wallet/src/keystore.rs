// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keystore — Argon2id key derivation + AES-256-GCM encryption.
//!
//! **Design choice: single passphrase for all keys.**
//! The keystore uses one master passphrase to encrypt all private keys,
//! rather than per-key passphrases. This simplifies the UX (one unlock
//! per session) and matches the wallet model used by most blockchain
//! implementations. Per-key passphrases can be layered on top if needed
//! in a future version via an HSM or external signer interface.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use noble_crypto::keys::{NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};
use noble_crypto::{
    SCHEME_FAUCET_PASSPHRASE, SCHEME_P2P_IDENTITY, SCHEME_SECP256K1,
    SCHEME_TLS_KEY, SCHEME_TOTP_SECRET, SCHEME_VALIDATOR_SECP256K1,
};

use crate::error::WalletError;

/// JSON-serialized per-key encrypted file.
#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    scheme_id: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Minimum passphrase length (characters).
const MIN_PASSPHRASE_LEN: usize = 12;

/// Maximum consecutive failed unlock attempts before lockout.
const MAX_UNLOCK_ATTEMPTS: usize = 5;

/// Cooldown period after exceeding max unlock attempts (seconds).
const UNLOCK_COOLDOWN_SECS: u64 = 300; // 5 minutes

/// Manages encrypted private keys on disk.
pub struct KeyStore {
    path: PathBuf,
    /// Decrypted keys loaded on unlock. `None` means locked.
    unlocked_keys: Option<HashMap<Vec<u8>, NoblePrivateKey>>,
    /// Consecutive failed unlock attempts.
    failed_attempts: usize,
    /// When the lockout expires (if any).
    lockout_until: Option<Instant>,
}

impl KeyStore {
    /// Create a new keystore backed by the given directory.
    /// Creates the directory if it does not exist.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        tracing::info!(task = "wallet_key", "creating new keystore");
        Ok(Self {
            path,
            unlocked_keys: None,
            failed_attempts: 0,
            lockout_until: None,
        })
    }

    /// Validate that a passphrase meets minimum strength requirements.
    fn validate_passphrase(passphrase: &str) -> Result<(), WalletError> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(WalletError::PassphraseTooWeak(format!(
                "minimum {} characters required, got {}",
                MIN_PASSPHRASE_LEN,
                passphrase.len()
            )));
        }
        Ok(())
    }

    /// Check if the keystore is currently in brute-force lockout.
    fn check_lockout(&self) -> Result<(), WalletError> {
        if let Some(until) = self.lockout_until {
            if Instant::now() < until {
                let remaining = until.duration_since(Instant::now()).as_secs();
                return Err(WalletError::TooManyAttempts {
                    attempts: self.failed_attempts,
                    cooldown_secs: remaining + 1,
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if the keystore already contains a key with the given scheme.
    pub fn has_scheme(&self, scheme_id: u8) -> Result<bool, WalletError> {
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(hex_str) = name_str.strip_suffix(".json") {
                if let Ok(wire_bytes) = hex::decode(hex_str) {
                    if let Some(&first) = wire_bytes.first() {
                        if first == scheme_id {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Generate a new key for the given scheme, encrypt it, and store to disk.
    /// If the keystore is currently unlocked, the new key is also added to the
    /// in-memory map so it can be used immediately without re-unlock.
    ///
    /// Passphrase must be at least 12 characters.
    pub fn create_key(
        &mut self,
        scheme_id: u8,
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        Self::validate_passphrase(passphrase)?;

        if self.has_scheme(scheme_id)? {
            return Err(WalletError::DuplicateKey(format!(
                "a key with scheme {scheme_id:#04x} already exists"
            )));
        }

        let (secret_key, priv_key) = match scheme_id {
            SCHEME_SECP256K1 => {
                let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
                let priv_key = NoblePrivateKey::Secp256k1(sk.clone());
                (sk, priv_key)
            }
            other => return Err(WalletError::UnsupportedScheme(other)),
        };

        let pub_key = priv_key.public_key();
        let file_path = self.key_file_path(&pub_key);

        if file_path.exists() {
            return Err(WalletError::DuplicateKey(hex::encode(
                pub_key.to_wire_bytes(),
            )));
        }

        let encrypted = encrypt_key(&secret_key, scheme_id, passphrase)?;
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&file_path, &json)?;

        // Restrict file permissions to owner-only (0o600) on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
        }

        // If unlocked, add to in-memory map for immediate use.
        if let Some(ref mut keys) = self.unlocked_keys {
            keys.insert(pub_key.to_wire_bytes(), priv_key);
        }

        Ok(pub_key)
    }

    /// List all public keys stored on disk.
    pub fn list_keys(&self) -> Result<Vec<NoblePublicKey>, WalletError> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(hex_str) = name_str.strip_suffix(".json") {
                if let Ok(wire_bytes) = hex::decode(hex_str) {
                    if let Ok(pk) = NoblePublicKey::from_wire_bytes(&wire_bytes) {
                        keys.push(pk);
                    }
                }
            }
        }
        Ok(keys)
    }

    /// Sign a message using the private key corresponding to the given public key.
    /// Returns `Locked` if the keystore is not unlocked, or `KeyNotFound` if the
    /// key is not in the unlocked set.
    pub fn sign(
        &self,
        pubkey: &NoblePublicKey,
        message: &[u8; 32],
    ) -> Result<SignatureEnvelope, WalletError> {
        let keys = self.unlocked_keys.as_ref().ok_or(WalletError::Locked)?;
        let wire = pubkey.to_wire_bytes();
        let priv_key = keys
            .get(&wire)
            .ok_or_else(|| WalletError::KeyNotFound(hex::encode(&wire)))?;
        let envelope = priv_key.sign(message)?;
        Ok(envelope)
    }

    /// Delete a key from disk after verifying the passphrase.
    pub fn delete_key(
        &mut self,
        pubkey: &NoblePublicKey,
        _passphrase: &str,
    ) -> Result<(), WalletError> {
        let file_path = self.key_file_path(pubkey);
        if !file_path.exists() {
            return Err(WalletError::KeyNotFound(hex::encode(
                pubkey.to_wire_bytes(),
            )));
        }

        // Remove file (no passphrase verification — deletion is protected
        // by TOTP auth and the gateway-key guard upstream).
        fs::remove_file(&file_path)?;

        // Remove from unlocked keys if present.
        if let Some(ref mut keys) = self.unlocked_keys {
            keys.remove(&pubkey.to_wire_bytes());
        }

        Ok(())
    }

    /// Delete all keystore files for a given internal scheme ID (0x80+).
    ///
    /// Used to remove raw entries (e.g., faucet passphrase) before re-storing.
    pub fn delete_by_scheme(&mut self, scheme_id: u8) {
        if let Ok(entries) = fs::read_dir(&self.path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".json") {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if let Ok(enc) = serde_json::from_str::<serde_json::Value>(&content) {
                            if enc.get("scheme_id").and_then(|v| v.as_u64()) == Some(scheme_id as u64) {
                                if let Err(e) = fs::remove_file(entry.path()) {
                                    tracing::warn!("Failed to delete keystore file {:?}: {e}", entry.path());
                                }
                            }
                        }
                    }
                }
            }
        }
        // Also remove from unlocked keys if present.
        if let Some(ref mut keys) = self.unlocked_keys {
            keys.retain(|_, v| v.scheme_id() != scheme_id);
        }
    }

    /// Generate a new key from a BIP-39 mnemonic phrase.
    ///
    /// 1. Generates a random mnemonic (12 or 24 words).
    /// 2. Derives a seed via PBKDF2 (BIP-39 standard, empty passphrase).
    /// 3. Derives child key at m/44'/9999'/0'/0/0 via BIP-32.
    /// 4. Stores the derived secp256k1 key encrypted with the given passphrase.
    /// 5. Returns the mnemonic words and the corresponding public key.
    ///
    /// **The mnemonic must be backed up by the user** — it cannot be recovered
    /// from the encrypted key file.
    ///
    /// The encryption passphrase can be empty — Argon2id+AES-GCM still runs
    /// and `walletUnlock("")` works correctly.
    pub fn create_key_from_mnemonic(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
    ) -> Result<(String, NoblePublicKey), WalletError> {
        self.create_key_from_mnemonic_inner(word_count, encryption_passphrase, None, &[0u8; 32])
    }

    /// Generate a mnemonic-derived secp256k1 key and optionally write
    /// the same secret to `validator_key_path` (encrypted with `chain_meta`).
    /// This ensures validator key = wallet key in a single atomic operation
    /// while the secret is still in memory.
    pub fn create_key_from_mnemonic_with_validator(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
        validator_key_path: &std::path::Path,
        chain_meta: &[u8; 32],
    ) -> Result<(String, NoblePublicKey), WalletError> {
        self.create_key_from_mnemonic_inner(word_count, encryption_passphrase, Some(validator_key_path), chain_meta)
    }

    fn create_key_from_mnemonic_inner(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
        validator_key_path: Option<&std::path::Path>,
        chain_meta: &[u8; 32],
    ) -> Result<(String, NoblePublicKey), WalletError> {

        if word_count != 12 && word_count != 24 {
            return Err(WalletError::Crypto(format!(
                "word_count must be 12 or 24, got {word_count}"
            )));
        }

        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists".into(),
            ));
        }

        // Generate mnemonic
        let mnemonic = bip39::Mnemonic::generate(word_count)
            .map_err(|e| WalletError::Crypto(format!("mnemonic generation: {e}")))?;

        let mnemonic_str = mnemonic.words().collect::<Vec<_>>().join(" ");

        // Derive seed (empty BIP-39 passphrase by default)
        let mut seed = mnemonic.to_seed("");

        // Derive secp256k1 key at m/44'/9999'/0'/0/0
        let child = bip32::XPrv::derive_from_path(
            seed,
            &"m/44'/9999'/0'/0/0"
                .parse()
                .map_err(|e: bip32::Error| WalletError::Crypto(format!("derivation path: {e}")))?,
        )
        .map_err(|e| {
            seed.zeroize();
            WalletError::Crypto(format!("BIP-32 derivation: {e}"))
        })?;
        seed.zeroize();

        let secret_key = child.to_bytes();
        let mut sk_bytes: Vec<u8> = secret_key.to_vec();

        let priv_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
        let pub_key = priv_key.public_key();

        let file_path = self.key_file_path(&pub_key);
        if file_path.exists() {
            sk_bytes.zeroize();
            return Err(WalletError::DuplicateKey(hex::encode(
                pub_key.to_wire_bytes(),
            )));
        }

        // Write validator.key with the same secret (before zeroize) if requested.
        if let Some(vk_path) = validator_key_path {
            let mut raw = vec![SCHEME_SECP256K1];
            raw.extend_from_slice(&sk_bytes);
            let result = noble_crypto::file_encrypt::encrypt_file_data(&raw, chain_meta);
            raw.zeroize();
            let file_bytes = result
                .map_err(|e| WalletError::Crypto(format!("encrypt validator.key: {e}")))?;
            if let Some(parent) = vk_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(vk_path, &file_bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(vk_path, fs::Permissions::from_mode(0o600));
            }
        }

        let encrypted = encrypt_key(&sk_bytes, SCHEME_SECP256K1, encryption_passphrase)?;
        sk_bytes.zeroize();
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&file_path, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
        }

        if let Some(ref mut keys) = self.unlocked_keys {
            keys.insert(pub_key.to_wire_bytes(), priv_key);
        }

        Ok((mnemonic_str, pub_key))
    }

    /// Recover a key from an existing BIP-39 mnemonic phrase.
    ///
    /// 1. Parses and validates the mnemonic.
    /// 2. Derives the same seed/path as `create_key_from_mnemonic`.
    /// 3. If the key already exists, returns it without re-encrypting.
    /// 4. Otherwise, encrypts and stores the derived key.
    ///
    /// The encryption passphrase can be empty.
    pub fn recover_from_mnemonic(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        self.recover_from_mnemonic_inner(mnemonic_words, encryption_passphrase, None, &[0u8; 32])
    }

    /// Recover a wallet key from mnemonic and optionally write the same
    /// secret to `validator_key_path`.
    pub fn recover_from_mnemonic_with_validator(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
        validator_key_path: &std::path::Path,
        chain_meta: &[u8; 32],
    ) -> Result<NoblePublicKey, WalletError> {
        self.recover_from_mnemonic_inner(mnemonic_words, encryption_passphrase, Some(validator_key_path), chain_meta)
    }

    fn recover_from_mnemonic_inner(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
        validator_key_path: Option<&std::path::Path>,
        chain_meta: &[u8; 32],
    ) -> Result<NoblePublicKey, WalletError> {

        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists; delete it first to import a different mnemonic".into(),
            ));
        }

        let mnemonic: bip39::Mnemonic = mnemonic_words
            .parse()
            .map_err(|e: bip39::Error| WalletError::Crypto(format!("invalid mnemonic: {e}")))?;

        let mut seed = mnemonic.to_seed("");

        let child = bip32::XPrv::derive_from_path(
            seed,
            &"m/44'/9999'/0'/0/0"
                .parse()
                .map_err(|e: bip32::Error| WalletError::Crypto(format!("derivation path: {e}")))?,
        )
        .map_err(|e| {
            seed.zeroize();
            WalletError::Crypto(format!("BIP-32 derivation: {e}"))
        })?;
        seed.zeroize();

        let secret_key = child.to_bytes();
        let mut sk_bytes: Vec<u8> = secret_key.to_vec();

        let priv_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
        let pub_key = priv_key.public_key();

        let file_path = self.key_file_path(&pub_key);
        if file_path.exists() {
            // Key already on disk — still write validator.key if requested and missing.
            if let Some(vk_path) = validator_key_path {
                if !vk_path.exists() {
                    let mut raw = vec![SCHEME_SECP256K1];
                    raw.extend_from_slice(&sk_bytes);
                    if let Ok(file_bytes) = noble_crypto::file_encrypt::encrypt_file_data(&raw, chain_meta) {
                        let _ = fs::write(vk_path, &file_bytes);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(vk_path, fs::Permissions::from_mode(0o600));
                        }
                    }
                }
            }
            sk_bytes.zeroize();
            return Ok(pub_key);
        }

        // Write validator.key with the same secret (before zeroize) if requested.
        if let Some(vk_path) = validator_key_path {
            let mut raw = vec![SCHEME_SECP256K1];
            raw.extend_from_slice(&sk_bytes);
            let result = noble_crypto::file_encrypt::encrypt_file_data(&raw, chain_meta);
            raw.zeroize();
            let file_bytes = result
                .map_err(|e| WalletError::Crypto(format!("encrypt validator.key: {e}")))?;
            if let Some(parent) = vk_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(vk_path, &file_bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(vk_path, fs::Permissions::from_mode(0o600));
            }
        }

        let encrypted = encrypt_key(&sk_bytes, SCHEME_SECP256K1, encryption_passphrase)?;
        sk_bytes.zeroize();
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&file_path, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
        }

        if let Some(ref mut keys) = self.unlocked_keys {
            keys.insert(pub_key.to_wire_bytes(), priv_key);
        }

        Ok(pub_key)
    }

    /// Unlock the keystore by decrypting all key files with the given passphrase.
    /// If any key file fails to decrypt, returns `InvalidPassphrase`.
    ///
    /// Enforces brute-force protection: after 5 consecutive failed attempts,
    /// the keystore enters a 5-minute cooldown period.
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), WalletError> {
        self.check_lockout()?;

        let mut keys = HashMap::new();

        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".json") {
                continue;
            }

            let json = fs::read_to_string(entry.path())?;
            let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

            let mut secret = match decrypt_key(&encrypted, passphrase) {
                Ok(s) => s,
                Err(_) => {
                    self.failed_attempts += 1;
                    if self.failed_attempts >= MAX_UNLOCK_ATTEMPTS {
                        self.lockout_until = Some(
                            Instant::now() + std::time::Duration::from_secs(UNLOCK_COOLDOWN_SECS),
                        );
                    }
                    return Err(WalletError::InvalidPassphrase);
                }
            };

            let priv_key = match encrypted.scheme_id {
                SCHEME_SECP256K1 => NoblePrivateKey::Secp256k1(secret.clone()),
                SCHEME_VALIDATOR_SECP256K1 => NoblePrivateKey::ValidatorSecp256k1(secret.clone()),
                SCHEME_P2P_IDENTITY => NoblePrivateKey::P2pIdentity(secret.clone()),
                SCHEME_TLS_KEY => NoblePrivateKey::TlsKey(secret.clone()),
                SCHEME_TOTP_SECRET => NoblePrivateKey::TotpSecret(secret.clone()),
                SCHEME_FAUCET_PASSPHRASE => NoblePrivateKey::FaucetPassphrase(secret.clone()),
                other => {
                    secret.zeroize();
                    return Err(WalletError::UnsupportedScheme(other));
                }
            };

            let pub_key = priv_key.public_key();
            // Internal keys (0x80+) use their internal scheme_id in the map key
            // so the in-memory representation matches the on-disk filename.
            let map_key = if noble_crypto::is_signing_scheme(encrypted.scheme_id) {
                pub_key.to_wire_bytes()
            } else {
                let mut w = Vec::with_capacity(1 + pub_key.key_bytes().len());
                w.push(encrypted.scheme_id);
                w.extend_from_slice(pub_key.key_bytes());
                w
            };
            keys.insert(map_key, priv_key);
            secret.zeroize();
        }

        // Successful unlock — reset brute-force counters
        self.failed_attempts = 0;
        self.lockout_until = None;
        self.unlocked_keys = Some(keys);
        tracing::debug!(task = "wallet_key", "key unlocked successfully");
        Ok(())
    }

    /// Lock the keystore, clearing all decrypted keys from memory.
    pub fn lock(&mut self) {
        self.unlocked_keys = None;
        tracing::debug!(task = "wallet_key", "key locked");
    }

    /// Returns `true` if the keystore is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked_keys.is_some()
    }

    /// Import a secp256k1 private key from WIF (Wallet Import Format) or raw hex.
    /// Returns the derived public key.
    ///
    /// The encryption passphrase can be empty.
    pub fn import_secp256k1_key(
        &mut self,
        key_input: &str,
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {

        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists".into(),
            ));
        }

        let mut secret_bytes = if key_input.len() == 64
            && key_input.chars().all(|c| c.is_ascii_hexdigit())
        {
            // Raw hex (32 bytes)
            hex::decode(key_input).map_err(|e| WalletError::InvalidKey(e.to_string()))?
        } else {
            // Try WIF decode (Base58Check)
            noble_crypto::bitcoin_addr::decode_wif(key_input)
                .map_err(|e| WalletError::InvalidKey(e.to_string()))?
        };

        let priv_key = NoblePrivateKey::Secp256k1(secret_bytes.clone());
        let pub_key = priv_key.public_key();
        let file_path = self.key_file_path(&pub_key);

        if file_path.exists() {
            secret_bytes.zeroize();
            return Err(WalletError::DuplicateKey(hex::encode(
                pub_key.to_wire_bytes(),
            )));
        }

        let encrypted = encrypt_key(&secret_bytes, SCHEME_SECP256K1, passphrase)?;
        secret_bytes.zeroize();
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&file_path, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
        }

        if let Some(ref mut keys) = self.unlocked_keys {
            keys.insert(pub_key.to_wire_bytes(), priv_key);
        }

        Ok(pub_key)
    }

    /// Store arbitrary raw bytes under an internal (non-signing) scheme ID.
    ///
    /// The bytes are encrypted with the keystore passphrase and stored on disk.
    /// A synthetic "public key" (SHA-256 of the raw bytes) is used for the filename.
    /// For signing-capable internal schemes (ValidatorSecp256k1/ValidatorSecp256k1),
    /// the real public key is derived and used as the filename.
    ///
    /// The passphrase is validated only for on-chain wallet schemes; internal
    /// schemes accept any passphrase (including derived chain_meta keys).
    pub fn store_raw(
        &mut self,
        scheme_id: u8,
        raw_bytes: &[u8],
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        if self.has_scheme(scheme_id)? {
            return Err(WalletError::DuplicateKey(format!(
                "a key with scheme {scheme_id:#04x} already exists"
            )));
        }

        let priv_key = match scheme_id {
            SCHEME_VALIDATOR_SECP256K1 => NoblePrivateKey::ValidatorSecp256k1(raw_bytes.to_vec()),
            SCHEME_P2P_IDENTITY => NoblePrivateKey::P2pIdentity(raw_bytes.to_vec()),
            SCHEME_TLS_KEY => NoblePrivateKey::TlsKey(raw_bytes.to_vec()),
            SCHEME_TOTP_SECRET => NoblePrivateKey::TotpSecret(raw_bytes.to_vec()),
            SCHEME_FAUCET_PASSPHRASE => NoblePrivateKey::FaucetPassphrase(raw_bytes.to_vec()),
            other => return Err(WalletError::UnsupportedScheme(other)),
        };

        let pub_key = priv_key.public_key();

        // For internal keys (0x80+), the filename must use the internal scheme_id
        // rather than the public key's on-chain scheme (Secp256k1/Secp256k1), so
        // has_scheme() can find them by their actual scheme_id.
        let wire_bytes = if noble_crypto::is_signing_scheme(scheme_id) {
            pub_key.to_wire_bytes()
        } else {
            let mut w = Vec::with_capacity(1 + pub_key.key_bytes().len());
            w.push(scheme_id);
            w.extend_from_slice(pub_key.key_bytes());
            w
        };
        let file_name = format!("{}.json", hex::encode(&wire_bytes));
        let file_path = self.path.join(file_name);

        if file_path.exists() {
            return Err(WalletError::DuplicateKey(hex::encode(&wire_bytes)));
        }

        let encrypted = encrypt_key(raw_bytes, scheme_id, passphrase)?;
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&file_path, &json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
        }

        if let Some(ref mut keys) = self.unlocked_keys {
            keys.insert(wire_bytes, priv_key);
        }

        Ok(pub_key)
    }

    /// Retrieve the raw bytes for an internal (non-signing) scheme.
    ///
    /// The keystore must be unlocked. Scans unlocked keys for the first
    /// key matching the given scheme_id and returns its raw bytes.
    pub fn get_raw(&self, scheme_id: u8) -> Result<Vec<u8>, WalletError> {
        let keys = self.unlocked_keys.as_ref().ok_or(WalletError::Locked)?;
        for priv_key in keys.values() {
            if priv_key.scheme_id() == scheme_id {
                if let Some(raw) = priv_key.raw_bytes() {
                    return Ok(raw.to_vec());
                }
            }
        }
        Err(WalletError::KeyNotFound(format!(
            "no key with scheme {scheme_id:#04x}"
        )))
    }

    /// Re-encrypt every key file from `old_passphrase` to `new_passphrase`.
    ///
    /// For each `.json` key file the method decrypts with `old`, re-encrypts
    /// with `new`, and performs an atomic write (tmp + rename).  Returns the
    /// number of migrated key files.
    ///
    /// The keystore must be **locked** when calling this (in-memory keys are
    /// not touched).
    pub fn migrate_passphrase(
        &mut self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<usize, WalletError> {
        let mut migrated = 0usize;

        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".json") {
                continue;
            }

            let file_path = entry.path();
            let json = fs::read_to_string(&file_path)?;
            let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

            // Decrypt with old passphrase
            let secret = decrypt_key(&encrypted, old_passphrase)?;

            // Re-encrypt with new passphrase
            let new_encrypted = encrypt_key(&secret, encrypted.scheme_id, new_passphrase)?;
            let new_json = serde_json::to_string_pretty(&new_encrypted)?;

            // Atomic write: write to .tmp, then rename
            let tmp_path = file_path.with_extension("json.tmp");
            fs::write(&tmp_path, &new_json)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
            }
            fs::rename(&tmp_path, &file_path)?;

            migrated += 1;
        }

        Ok(migrated)
    }

    /// Compute the file path for a given public key.
    fn key_file_path(&self, pubkey: &NoblePublicKey) -> PathBuf {
        self.path
            .join(format!("{}.json", hex::encode(pubkey.to_wire_bytes())))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte AES key from a passphrase and salt using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], WalletError> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    Ok(key)
}

/// Encrypt a secret key with the given passphrase.
fn encrypt_key(
    secret_key: &[u8],
    scheme_id: u8,
    passphrase: &str,
) -> Result<EncryptedKeyFile, WalletError> {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let aes_key = derive_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret_key)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;

    Ok(EncryptedKeyFile {
        scheme_id,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt a secret key from an encrypted key file.
fn decrypt_key(file: &EncryptedKeyFile, passphrase: &str) -> Result<Vec<u8>, WalletError> {
    let salt = hex::decode(&file.salt).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce_bytes = hex::decode(&file.nonce).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let ciphertext =
        hex::decode(&file.ciphertext).map_err(|e| WalletError::Crypto(e.to_string()))?;

    let aes_key = derive_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| WalletError::Crypto(e.to_string()))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::sha256;
    use tempfile::tempdir;

    #[test]
    fn create_key_secp256k1() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "test-pass-long").unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_wire_bytes(), pk.to_wire_bytes());
    }

    #[test]
    fn create_key_secp256k1() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "test-pass-long").unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_wire_bytes(), pk.to_wire_bytes());
    }

    #[test]
    fn sign_with_created_key() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        // Unlock first (empty keystore), then create key so it's available.
        ks.unlock("test-pass-long").unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "test-pass-long").unwrap();

        let msg = sha256(b"wallet sign test");
        let envelope = ks.sign(&pk, msg.as_bytes()).unwrap();

        // Verify with the public key.
        assert!(pk.verify(msg.as_bytes(), &envelope).is_ok());
    }

    #[test]
    fn unlock_with_correct_passphrase() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("pass1-is-long!").unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "pass1-is-long!").unwrap();
        ks.lock();
        assert!(!ks.is_unlocked());

        // Unlock with correct passphrase.
        ks.unlock("pass1-is-long!").unwrap();
        assert!(ks.is_unlocked());

        // Should be able to sign.
        let msg = sha256(b"unlock test");
        assert!(ks.sign(&pk, msg.as_bytes()).is_ok());
    }

    #[test]
    fn unlock_with_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("correct-is-ok!").unwrap();
        let _pk = ks.create_key(SCHEME_SECP256K1, "correct-is-ok!").unwrap();
        ks.lock();

        // Unlock with wrong passphrase.
        let result = ks.unlock("wrong-is-long!");
        assert!(result.is_err());
        match result.unwrap_err() {
            WalletError::InvalidPassphrase => {}
            other => panic!("expected InvalidPassphrase, got: {other}"),
        }
    }

    #[test]
    fn lock_clears_keys() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("passphrase-ok").unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();

        // Sign works while unlocked.
        let msg = sha256(b"lock test");
        assert!(ks.sign(&pk, msg.as_bytes()).is_ok());

        // Lock and try again.
        ks.lock();
        let result = ks.sign(&pk, msg.as_bytes());
        assert!(matches!(result, Err(WalletError::Locked)));
    }

    #[test]
    fn sign_while_locked_fails() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        // Create key without unlocking (key file on disk but not in memory).
        let pk = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();

        let msg = sha256(b"locked sign test");
        let result = ks.sign(&pk, msg.as_bytes());
        assert!(matches!(result, Err(WalletError::Locked)));
    }

    #[test]
    fn delete_key_removes_file() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("passphrase-ok").unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 1);

        ks.delete_key(&pk, "passphrase-ok").unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn key_file_roundtrip() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("passphrase-ok").unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();

        // Sign while unlocked.
        let msg = sha256(b"roundtrip test");
        let sig1 = ks.sign(&pk, msg.as_bytes()).unwrap();

        // Lock, then unlock again (reload from disk).
        ks.lock();
        ks.unlock("passphrase-ok").unwrap();

        // Sign again — should produce a valid signature.
        let sig2 = ks.sign(&pk, msg.as_bytes()).unwrap();

        // Both signatures should verify.
        assert!(pk.verify(msg.as_bytes(), &sig1).is_ok());
        assert!(pk.verify(msg.as_bytes(), &sig2).is_ok());
    }

    #[test]
    fn empty_keystore() {
        let dir = tempdir().unwrap();
        let ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let keys = ks.list_keys().unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn multiple_keys_different_schemes() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let _pk1 = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();
        let _pk2 = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn duplicate_scheme_rejected_at_keystore_level() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();
        let result = ks.create_key(SCHEME_SECP256K1, "passphrase-ok");
        assert!(matches!(result, Err(WalletError::DuplicateKey(_))));
        // Different scheme still works
        ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();
    }

    #[test]
    fn argon2id_derive_deterministic() {
        let salt = [0xABu8; 32];
        let key1 = derive_key("my-passphrase", &salt).unwrap();
        let key2 = derive_key("my-passphrase", &salt).unwrap();
        assert_eq!(key1, key2, "same passphrase + salt must produce same key");

        let key3 = derive_key("different-pass", &salt).unwrap();
        assert_ne!(
            key1, key3,
            "different passphrase must produce different key"
        );
    }

    #[test]
    fn short_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let result = ks.create_key(SCHEME_SECP256K1, "short");
        assert!(
            matches!(result, Err(WalletError::PassphraseTooWeak(_))),
            "expected PassphraseTooWeak, got: {result:?}"
        );
    }

    #[test]
    fn exactly_min_passphrase_accepted() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        // 12 chars exactly should pass
        let result = ks.create_key(SCHEME_SECP256K1, "123456789012");
        assert!(result.is_ok(), "12-char passphrase should be accepted");
    }

    #[test]
    fn brute_force_lockout() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("correct-is-ok!").unwrap();
        let _pk = ks.create_key(SCHEME_SECP256K1, "correct-is-ok!").unwrap();
        ks.lock();

        // Exhaust attempts with wrong passphrase
        for _ in 0..MAX_UNLOCK_ATTEMPTS {
            let _ = ks.unlock("wrong-is-long!");
        }

        // Now even the correct passphrase should be rejected
        let result = ks.unlock("correct-is-ok!");
        assert!(
            matches!(result, Err(WalletError::TooManyAttempts { .. })),
            "expected TooManyAttempts, got: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();
        let file_path = dir
            .path()
            .join("keys")
            .join(format!("{}.json", hex::encode(pk.to_wire_bytes())));
        let perms = std::fs::metadata(&file_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "key file should have 0o600 permissions"
        );
    }

    // --- secp256k1 key import tests ---

    #[test]
    fn import_secp256k1_hex_key() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("passphrase-ok").unwrap();

        // Generate a secp256k1 keypair to get a known secret key
        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let hex_key = hex::encode(&sk);

        let pk = ks
            .import_secp256k1_key(&hex_key, "passphrase-ok")
            .unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        // Key should appear in list
        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);

        // Sign should work
        let msg = sha256(b"import hex test");
        let sig = ks.sign(&pk, msg.as_bytes()).unwrap();
        assert!(pk.verify(msg.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn import_secp256k1_duplicate_rejected() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("passphrase-ok").unwrap();

        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let hex_key = hex::encode(&sk);

        // First import succeeds
        ks.import_secp256k1_key(&hex_key, "passphrase-ok").unwrap();

        // Second import of same key fails
        let result = ks.import_secp256k1_key(&hex_key, "passphrase-ok");
        assert!(
            matches!(result, Err(WalletError::DuplicateKey(_))),
            "duplicate import should fail: {result:?}"
        );
    }

    // --- BIP-39 Mnemonic tests ---

    #[test]
    fn bip39_generate_24_word_mnemonic() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let (mnemonic, pk) = ks.create_key_from_mnemonic(24, "test-pass-long").unwrap();

        // Should be 24 words
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24, "expected 24 words, got {}", words.len());

        // Key should be secp256k1
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        // Key should be listed
        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn bip39_generate_12_word_mnemonic() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let (mnemonic, pk) = ks.create_key_from_mnemonic(12, "test-pass-long").unwrap();

        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12, "expected 12 words, got {}", words.len());
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);
    }

    #[test]
    fn bip39_recover_same_key() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let (mnemonic, pk1) = ks.create_key_from_mnemonic(24, "test-pass-long").unwrap();

        // Recover from the same mnemonic (in a new keystore to ensure fresh state)
        let dir2 = tempdir().unwrap();
        let mut ks2 = KeyStore::new(dir2.path().join("keys")).unwrap();
        let pk2 = ks2
            .recover_from_mnemonic(&mnemonic, "test-pass-long")
            .unwrap();

        assert_eq!(
            pk1.to_wire_bytes(),
            pk2.to_wire_bytes(),
            "recovered key must match original"
        );
    }

    #[test]
    fn mnemonic_empty_passphrase_succeeds() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        // Empty passphrase should work for mnemonic-based key generation
        let (mnemonic, pk) = ks.create_key_from_mnemonic(24, "").unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        // Unlock with empty passphrase should work
        ks.lock();
        ks.unlock("").unwrap();
        assert!(ks.is_unlocked());

        // Recover with empty passphrase should also work
        let dir2 = tempdir().unwrap();
        let mut ks2 = KeyStore::new(dir2.path().join("keys")).unwrap();
        let pk2 = ks2.recover_from_mnemonic(&mnemonic, "").unwrap();
        assert_eq!(pk.to_wire_bytes(), pk2.to_wire_bytes());
    }

    #[test]
    fn migrate_passphrase_empty_to_strong() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();

        // Create a mnemonic key with empty passphrase (mnemonic path allows empty)
        let (_, pk1) = ks.create_key_from_mnemonic(24, "").unwrap();

        // Verify empty passphrase unlocks
        ks.unlock("").unwrap();
        let msg = sha256(b"migrate test");
        assert!(ks.sign(&pk1, msg.as_bytes()).is_ok());
        ks.lock();

        // Migrate to a strong passphrase
        let new_pass = "a]3Kf9$mLpQ2x!Rv7WnBhYs0+dT6UeJi";
        let count = ks.migrate_passphrase("", new_pass).unwrap();
        assert_eq!(count, 1, "should migrate 1 key file");

        // Old passphrase no longer works
        let result = ks.unlock("");
        assert!(result.is_err(), "empty passphrase must fail after migration");

        // New passphrase works
        ks.unlock(new_pass).unwrap();
        assert!(ks.sign(&pk1, msg.as_bytes()).is_ok());
    }

    #[test]
    fn migrate_passphrase_empty_keystore() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let count = ks.migrate_passphrase("old-pass-ok!!", "new-pass-ok!!").unwrap();
        assert_eq!(count, 0, "empty keystore migrates 0 keys");
    }

    #[test]
    fn bip39_invalid_mnemonic_rejected() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let result = ks.recover_from_mnemonic(
            "invalid words that are not a valid bip39 mnemonic phrase at all",
            "test-pass-long",
        );
        assert!(result.is_err(), "invalid mnemonic must be rejected");
    }

    // --- Internal scheme (store_raw / get_raw) tests ---

    #[test]
    fn store_and_get_raw_p2p_identity() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let pk = ks
            .store_raw(SCHEME_P2P_IDENTITY, &raw, "passphrase-ok")
            .unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1); // synthetic pubkey

        // Unlock and retrieve
        ks.unlock("passphrase-ok").unwrap();
        let got = ks.get_raw(SCHEME_P2P_IDENTITY).unwrap();
        assert_eq!(got, raw);
    }

    #[test]
    fn store_raw_duplicate_rejected() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.store_raw(SCHEME_TOTP_SECRET, b"secret1", "passphrase-ok")
            .unwrap();
        let result = ks.store_raw(SCHEME_TOTP_SECRET, b"secret2", "passphrase-ok");
        assert!(
            matches!(result, Err(WalletError::DuplicateKey(_))),
            "duplicate scheme must be rejected"
        );
    }

    #[test]
    fn get_raw_while_locked_fails() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.store_raw(SCHEME_TLS_KEY, b"tls-key-bytes", "passphrase-ok")
            .unwrap();
        let result = ks.get_raw(SCHEME_TLS_KEY);
        assert!(
            matches!(result, Err(WalletError::Locked)),
            "get_raw while locked must fail"
        );
    }

    #[test]
    fn store_raw_validator_key() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let pk = ks
            .store_raw(SCHEME_VALIDATOR_SECP256K1, &sk, "passphrase-ok")
            .unwrap();
        // Validator Secp256k1 derives a real Secp256k1 public key
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        // Unlock, get raw, and verify it round-trips
        ks.unlock("passphrase-ok").unwrap();
        let got = ks.get_raw(SCHEME_VALIDATOR_SECP256K1).unwrap();
        assert_eq!(got, sk);
    }

    #[test]
    fn mixed_signing_and_internal_keys() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();

        // Create a wallet key (on-chain signing)
        ks.create_key(SCHEME_SECP256K1, "passphrase-ok").unwrap();

        // Store internal keys
        ks.store_raw(SCHEME_P2P_IDENTITY, b"p2p-proto-bytes", "passphrase-ok")
            .unwrap();
        ks.store_raw(SCHEME_TOTP_SECRET, b"totp-base32", "passphrase-ok")
            .unwrap();

        // list_keys returns only on-chain signing keys (NoblePublicKey-compatible)
        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        // Total files on disk includes internal keys
        let total_files = std::fs::read_dir(dir.path().join("keys"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".json"))
            .count();
        assert_eq!(total_files, 3);

        // Unlock loads everything
        ks.unlock("passphrase-ok").unwrap();
        assert!(ks.get_raw(SCHEME_P2P_IDENTITY).is_ok());
        assert!(ks.get_raw(SCHEME_TOTP_SECRET).is_ok());
    }
}
