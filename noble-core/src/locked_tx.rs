// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Locked transaction encryption and decryption.
//!
//! A locked transaction (0x06) encrypts metadata values and the document
//! checksum with AES-256-GCM using a password-derived key. An unlocking
//! transaction (0x07) publishes the password, enabling the node to decrypt
//! and re-index the locked fields.
//!
//! Key derivation: `key = SHA-256(password || salt)` (32 bytes).
//! Encryption: AES-256-GCM with a 12-byte nonce per field.
//!
//! Already-encrypted fields (encrypted_locator) get an additional password
//! layer on top. Unlocking strips only the password layer.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use noble_crypto::{sha256, Hash256};

use crate::transaction::Transaction;

/// Metadata key prefixes for locked transactions.
pub const META_LOCKED_CHECKSUM: &str = "locked:checksum";
pub const META_LOCKED_SALT: &str = "locked:salt";
pub const META_LOCKED_NONCE: &str = "locked:nonce";

/// Metadata key prefixes for unlocking transactions.
pub const META_UNLOCK_TXID: &str = "unlock:txid";
pub const META_UNLOCK_PASSWORD: &str = "unlock:password";

/// Decrypted fields from a locked transaction.
#[derive(Debug, Clone)]
pub struct DecryptedFields {
    /// The real document checksum (was encrypted in metadata).
    pub checksum: Hash256,
    /// Decrypted metadata entries: (key, decrypted_value_bytes).
    /// Only includes user metadata — locked:* keys are excluded.
    pub metadata: Vec<(String, Vec<u8>)>,
}

/// Derive the AES-256-GCM encryption key from a password and salt.
///
/// `key = SHA-256(password || salt)` — 32 bytes, suitable for AES-256.
pub fn derive_lock_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(password.len() + salt.len());
    preimage.extend_from_slice(password);
    preimage.extend_from_slice(salt);
    sha256(&preimage).0
}

/// Encrypt a field value with AES-256-GCM.
///
/// Returns the ciphertext (plaintext.len() + 16 bytes GCM tag).
pub fn encrypt_field(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key init: {e}"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| format!("AES encrypt: {e}"))
}

/// Decrypt a field value with AES-256-GCM.
///
/// The ciphertext must include the 16-byte GCM tag.
pub fn decrypt_field(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key init: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| format!("AES decrypt: {e}"))
}

/// Decrypt a locked transaction's fields given the password.
///
/// Extracts `locked:salt` and `locked:nonce` from the locked tx's metadata,
/// derives the key, decrypts `locked:checksum` and all user metadata values.
pub fn decrypt_locked_tx(locked_tx: &Transaction, password: &[u8]) -> Result<DecryptedFields, String> {
    // Extract required locked:* metadata
    let salt_hex = locked_tx.metadata.iter()
        .find(|m| m.key == META_LOCKED_SALT)
        .map(|m| std::str::from_utf8(&m.value).unwrap_or(""))
        .ok_or("missing locked:salt")?;
    let nonce_hex = locked_tx.metadata.iter()
        .find(|m| m.key == META_LOCKED_NONCE)
        .map(|m| std::str::from_utf8(&m.value).unwrap_or(""))
        .ok_or("missing locked:nonce")?;
    let checksum_hex = locked_tx.metadata.iter()
        .find(|m| m.key == META_LOCKED_CHECKSUM)
        .map(|m| std::str::from_utf8(&m.value).unwrap_or(""))
        .ok_or("missing locked:checksum")?;

    let salt = hex::decode(salt_hex).map_err(|e| format!("invalid salt hex: {e}"))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce hex: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err(format!("nonce must be 12 bytes, got {}", nonce_bytes.len()));
    }
    let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

    let key = derive_lock_key(password, &salt);

    // Decrypt checksum
    let checksum_ct = hex::decode(checksum_hex).map_err(|e| format!("invalid checksum ciphertext hex: {e}"))?;
    let checksum_pt = decrypt_field(&checksum_ct, &key, &nonce)?;
    // The plaintext is the hex-encoded checksum string
    let checksum_str = std::str::from_utf8(&checksum_pt)
        .map_err(|_| "decrypted checksum is not valid UTF-8")?;
    let checksum = Hash256::from_hex(checksum_str)
        .map_err(|e| format!("decrypted checksum is not valid hash: {e}"))?;

    // Decrypt user metadata values (skip locked:* keys).
    // Entries processed in alphabetical key order — the encryption side MUST
    // use the same order so nonce counters align.
    let mut user_entries: Vec<_> = locked_tx.metadata.iter()
        .filter(|e| !e.key.starts_with("locked:"))
        .collect();
    user_entries.sort_by(|a, b| a.key.cmp(&b.key));

    let mut decrypted_meta = Vec::new();
    let mut nonce_counter = 1u32; // nonce 0 = checksum, 1+ = metadata entries

    for entry in &user_entries {

        // Each user metadata value uses nonce XORed with a counter for uniqueness
        let mut field_nonce = nonce;
        let counter_bytes = nonce_counter.to_be_bytes();
        for i in 0..4 {
            field_nonce[8 + i] ^= counter_bytes[i];
        }
        nonce_counter += 1;

        let ct = hex::decode(std::str::from_utf8(&entry.value).unwrap_or(""))
            .map_err(|e| format!("metadata '{}' ciphertext hex invalid: {e}", entry.key))?;
        let pt = decrypt_field(&ct, &key, &field_nonce)?;
        decrypted_meta.push((entry.key.clone(), pt));
    }

    Ok(DecryptedFields {
        checksum,
        metadata: decrypted_meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_deterministic() {
        let k1 = derive_lock_key(b"password123", b"salt_16_bytes!!!");
        let k2 = derive_lock_key(b"password123", b"salt_16_bytes!!!");
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_derivation_different_passwords() {
        let k1 = derive_lock_key(b"password1", b"salt");
        let k2 = derive_lock_key(b"password2", b"salt");
        assert_ne!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_lock_key(b"test", b"salt");
        let nonce = [0u8; 12];
        let plaintext = b"hello world";

        let ct = encrypt_field(plaintext, &key, &nonce).unwrap();
        assert_ne!(ct.as_slice(), plaintext);
        assert_eq!(ct.len(), plaintext.len() + 16); // +16 GCM tag

        let pt = decrypt_field(&ct, &key, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let key1 = derive_lock_key(b"correct", b"salt");
        let key2 = derive_lock_key(b"wrong", b"salt");
        let nonce = [0u8; 12];

        let ct = encrypt_field(b"secret data", &key1, &nonce).unwrap();
        let result = decrypt_field(&ct, &key2, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = derive_lock_key(b"test", b"salt");
        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];

        let ct = encrypt_field(b"secret", &key, &nonce1).unwrap();
        let result = decrypt_field(&ct, &key, &nonce2);
        assert!(result.is_err());
    }

    #[test]
    fn multi_field_encrypt_decrypt_roundtrip() {
        use crate::transaction::Transaction;
        use crate::metadata::MetadataEntry;
        use crate::constants::TX_TYPE_LOCKED;
        use noble_crypto::SignatureEnvelope;

        let password = b"my_secret_password";
        let salt = b"0123456789abcdef"; // 16 bytes
        let nonce = [42u8; 12];
        let key = derive_lock_key(password, salt);

        // Real values to encrypt
        let real_checksum = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let real_author = b"Alice";
        let real_title = b"My Document";

        // Encrypt checksum (nonce counter 0 = base nonce)
        let checksum_ct = encrypt_field(real_checksum.as_bytes(), &key, &nonce).unwrap();

        // Encrypt metadata values in alphabetical key order: "author" < "title"
        // author = counter 1, title = counter 2
        let mut nonce_1 = nonce;
        let c1 = 1u32.to_be_bytes();
        for i in 0..4 { nonce_1[8 + i] ^= c1[i]; }
        let author_ct = encrypt_field(real_author, &key, &nonce_1).unwrap();

        let mut nonce_2 = nonce;
        let c2 = 2u32.to_be_bytes();
        for i in 0..4 { nonce_2[8 + i] ^= c2[i]; }
        let title_ct = encrypt_field(real_title, &key, &nonce_2).unwrap();

        // Build a locked transaction
        let tx = Transaction {
            version: 1,
            tx_type: TX_TYPE_LOCKED,
            inputs: vec![],
            outputs: vec![],
            checksum: Hash256::ZERO,
            timestamp: 1000,
            issuer_sig: SignatureEnvelope { scheme_id: 0x02, public_key: vec![0; 33], signature: vec![0; 64] },
            additional_sigs: vec![],
            metadata: vec![
                // Insert in non-alphabetical order to test sorting
                MetadataEntry { key: "title".into(), value: hex::encode(&title_ct).into_bytes() },
                MetadataEntry { key: "locked:checksum".into(), value: hex::encode(&checksum_ct).into_bytes() },
                MetadataEntry { key: "locked:salt".into(), value: hex::encode(salt).into_bytes() },
                MetadataEntry { key: "locked:nonce".into(), value: hex::encode(&nonce).into_bytes() },
                MetadataEntry { key: "author".into(), value: hex::encode(&author_ct).into_bytes() },
            ],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };

        // Decrypt
        let result = decrypt_locked_tx(&tx, password).unwrap();

        assert_eq!(result.checksum, Hash256::from_hex(real_checksum).unwrap());
        assert_eq!(result.metadata.len(), 2);
        // Sorted alphabetically: author < title
        assert_eq!(result.metadata[0].0, "author");
        assert_eq!(result.metadata[0].1, real_author);
        assert_eq!(result.metadata[1].0, "title");
        assert_eq!(result.metadata[1].1, real_title);
    }
}
