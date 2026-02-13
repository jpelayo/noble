// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Encrypted keystore — Argon2id key derivation + AES-256-GCM encryption.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use noble_crypto::keys::{NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};
use noble_crypto::{SCHEME_ED25519, SCHEME_SECP256K1};

use crate::error::WalletError;

/// JSON-serialized per-key encrypted file.
#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    scheme_id: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Manages encrypted private keys on disk.
pub struct KeyStore {
    path: PathBuf,
    /// Decrypted keys loaded on unlock. `None` means locked.
    unlocked_keys: Option<HashMap<Vec<u8>, NoblePrivateKey>>,
}

impl KeyStore {
    /// Create a new keystore backed by the given directory.
    /// Creates the directory if it does not exist.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            unlocked_keys: None,
        })
    }

    /// Generate a new key for the given scheme, encrypt it, and store to disk.
    /// If the keystore is currently unlocked, the new key is also added to the
    /// in-memory map so it can be used immediately without re-unlock.
    pub fn create_key(
        &mut self,
        scheme_id: u8,
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        let (secret_key, priv_key) = match scheme_id {
            SCHEME_ED25519 => {
                let (sk, _pk) = noble_crypto::ed25519::generate_keypair();
                let priv_key = NoblePrivateKey::Ed25519(sk.clone());
                (sk, priv_key)
            }
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
        fs::write(&file_path, json)?;

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
        passphrase: &str,
    ) -> Result<(), WalletError> {
        let file_path = self.key_file_path(pubkey);
        if !file_path.exists() {
            return Err(WalletError::KeyNotFound(hex::encode(
                pubkey.to_wire_bytes(),
            )));
        }

        // Verify passphrase by attempting to decrypt.
        let json = fs::read_to_string(&file_path)?;
        let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;
        let _secret = decrypt_key(&encrypted, passphrase)?;

        // Remove file.
        fs::remove_file(&file_path)?;

        // Remove from unlocked keys if present.
        if let Some(ref mut keys) = self.unlocked_keys {
            keys.remove(&pubkey.to_wire_bytes());
        }

        Ok(())
    }

    /// Unlock the keystore by decrypting all key files with the given passphrase.
    /// If any key file fails to decrypt, returns `InvalidPassphrase`.
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), WalletError> {
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

            let mut secret =
                decrypt_key(&encrypted, passphrase).map_err(|_| WalletError::InvalidPassphrase)?;

            let priv_key = match encrypted.scheme_id {
                SCHEME_ED25519 => NoblePrivateKey::Ed25519(secret.clone()),
                SCHEME_SECP256K1 => NoblePrivateKey::Secp256k1(secret.clone()),
                other => {
                    secret.zeroize();
                    return Err(WalletError::UnsupportedScheme(other));
                }
            };

            let pub_key = priv_key.public_key();
            keys.insert(pub_key.to_wire_bytes(), priv_key);
            secret.zeroize();
        }

        self.unlocked_keys = Some(keys);
        Ok(())
    }

    /// Lock the keystore, clearing all decrypted keys from memory.
    pub fn lock(&mut self) {
        self.unlocked_keys = None;
    }

    /// Returns `true` if the keystore is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked_keys.is_some()
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
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

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
    fn create_key_ed25519() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "test-pass").unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_ED25519);

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_wire_bytes(), pk.to_wire_bytes());
    }

    #[test]
    fn create_key_secp256k1() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, "test-pass").unwrap();
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
        ks.unlock("test-pass").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "test-pass").unwrap();

        let msg = sha256(b"wallet sign test");
        let envelope = ks.sign(&pk, msg.as_bytes()).unwrap();

        // Verify with the public key.
        assert!(pk.verify(msg.as_bytes(), &envelope).is_ok());
    }

    #[test]
    fn unlock_with_correct_passphrase() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("pass1").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "pass1").unwrap();
        ks.lock();
        assert!(!ks.is_unlocked());

        // Unlock with correct passphrase.
        ks.unlock("pass1").unwrap();
        assert!(ks.is_unlocked());

        // Should be able to sign.
        let msg = sha256(b"unlock test");
        assert!(ks.sign(&pk, msg.as_bytes()).is_ok());
    }

    #[test]
    fn unlock_with_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("correct").unwrap();
        let _pk = ks.create_key(SCHEME_ED25519, "correct").unwrap();
        ks.lock();

        // Unlock with wrong passphrase.
        let result = ks.unlock("wrong");
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
        ks.unlock("pass").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "pass").unwrap();

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
        let pk = ks.create_key(SCHEME_ED25519, "pass").unwrap();

        let msg = sha256(b"locked sign test");
        let result = ks.sign(&pk, msg.as_bytes());
        assert!(matches!(result, Err(WalletError::Locked)));
    }

    #[test]
    fn delete_key_removes_file() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("pass").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "pass").unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 1);

        ks.delete_key(&pk, "pass").unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn key_file_roundtrip() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("pass").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "pass").unwrap();

        // Sign while unlocked.
        let msg = sha256(b"roundtrip test");
        let sig1 = ks.sign(&pk, msg.as_bytes()).unwrap();

        // Lock, then unlock again (reload from disk).
        ks.lock();
        ks.unlock("pass").unwrap();

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
    fn multiple_keys() {
        let dir = tempdir().unwrap();
        let mut ks = KeyStore::new(dir.path().join("keys")).unwrap();
        let _pk1 = ks.create_key(SCHEME_ED25519, "pass").unwrap();
        let _pk2 = ks.create_key(SCHEME_ED25519, "pass").unwrap();
        let _pk3 = ks.create_key(SCHEME_SECP256K1, "pass").unwrap();

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
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
}
