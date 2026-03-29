// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Hybrid ECIES encryption for NOBLE encrypted document locators.
//!
//! Uses secp256k1 ECDH for key agreement.
//! Uses HKDF-SHA256 for key derivation and AES-256-GCM for symmetric encryption.
//!
//! Encryption flow (per recipient):
//! 1. Generate ephemeral keypair (matching recipient's scheme)
//! 2. ECDH(ephemeral_private, recipient_public) -> shared_secret
//! 3. HKDF-SHA256(shared_secret, "noble-locator-v1") -> derived_key
//! 4. AES-256-GCM(derived_key, data_key) -> encrypted_key

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::CryptoError;
use crate::keys::{NoblePrivateKey, NoblePublicKey};

/// HKDF info string for NOBLE locator key derivation.
const HKDF_INFO: &[u8] = b"noble-locator-v1";

// ── Types ──

/// An encrypted payload with per-recipient key envelopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesPayload {
    /// AES-256-GCM encrypted data.
    pub ciphertext: Vec<u8>,
    /// GCM nonce for the data encryption.
    pub nonce: [u8; 12],
    /// Per-recipient key envelopes.
    pub recipients: Vec<EciesRecipient>,
}

/// A recipient's key envelope containing the encrypted data encryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EciesRecipient {
    /// The recipient's public key.
    pub recipient_pubkey: NoblePublicKey,
    /// Ephemeral public key used for ECDH (SEC1 compressed 33 bytes).
    pub ephemeral_pubkey: Vec<u8>,
    /// AES-256-GCM encrypted data key (32 bytes key + 16 bytes GCM tag = 48 bytes).
    pub encrypted_key: Vec<u8>,
    /// GCM nonce for the key encryption.
    pub key_nonce: [u8; 12],
}

// ── Internal helpers ──

/// Derive a 32-byte AES key from a shared secret using HKDF-SHA256.
///
/// Rejects all-zero shared secrets which indicate a small-order public key attack (H-ecies0).
fn hkdf_derive(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    // H-ecies0: reject all-zero shared secret (small-order point attack)
    if shared_secret.iter().all(|&b| b == 0) {
        return Err(CryptoError::EciesEncrypt(
            "ECDH produced all-zero shared secret (small-order point)".into(),
        ));
    }
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| CryptoError::EciesEncrypt(format!("HKDF expand: {e}")))?;
    Ok(okm)
}

/// Encrypt plaintext with AES-256-GCM using a random nonce.
fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EciesEncrypt(format!("AES-GCM encrypt: {e}")))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext with AES-256-GCM.
fn aes_decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::EciesDecrypt(format!("AES-GCM decrypt: {e}")))
}

// ── Public API ──

/// Encrypt a data encryption key (DEK) for a single recipient using ECIES.
///
/// Generates an ephemeral keypair matching the recipient's scheme, performs ECDH,
/// derives a wrapping key via HKDF, and encrypts the DEK with AES-256-GCM.
pub fn encrypt_for_recipient(
    recipient: &NoblePublicKey,
    dek: &[u8; 32],
) -> Result<EciesRecipient, CryptoError> {
    match recipient {
        NoblePublicKey::Secp256k1(pk_bytes) => {
            let their_pk = k256::PublicKey::from_sec1_bytes(pk_bytes)
                .map_err(|e| CryptoError::InvalidKey(format!("secp256k1: {e}")))?;

            let eph_secret = k256::ecdh::EphemeralSecret::random(&mut OsRng);
            let eph_public = eph_secret.public_key();
            let shared = eph_secret.diffie_hellman(&their_pk);

            let shared_bytes: [u8; 32] = shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .expect("secp256k1 shared secret is 32 bytes");

            let derived_key = hkdf_derive(&shared_bytes)?;
            let (encrypted_dek, key_nonce) = aes_encrypt(&derived_key, dek)?;

            Ok(EciesRecipient {
                recipient_pubkey: recipient.clone(),
                ephemeral_pubkey: eph_public.to_sec1_bytes().to_vec(),
                encrypted_key: encrypted_dek,
                key_nonce,
            })
        }
    }
}

/// Decrypt a data encryption key (DEK) using the recipient's private key.
///
/// Performs ECDH with the ephemeral public key, derives the wrapping key via HKDF,
/// and decrypts the DEK with AES-256-GCM.
pub fn decrypt_as_recipient(
    private_key: &NoblePrivateKey,
    ephemeral_pubkey: &[u8],
    encrypted_key: &[u8],
    key_nonce: &[u8; 12],
) -> Result<[u8; 32], CryptoError> {
    let shared_bytes = match private_key {
        NoblePrivateKey::Secp256k1(sk_bytes) | NoblePrivateKey::ValidatorSecp256k1(sk_bytes) => {
            let our_sk = k256::SecretKey::from_slice(sk_bytes)
                .map_err(|e| CryptoError::InvalidKey(format!("secp256k1: {e}")))?;
            let eph_pk = k256::PublicKey::from_sec1_bytes(ephemeral_pubkey)
                .map_err(|e| CryptoError::EciesDecrypt(format!("ephemeral key: {e}")))?;
            let shared = k256::ecdh::diffie_hellman(our_sk.to_nonzero_scalar(), eph_pk.as_affine());
            let bytes: [u8; 32] = shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .expect("secp256k1 shared secret is 32 bytes");
            bytes
        }
        NoblePrivateKey::P2pIdentity(_) | NoblePrivateKey::TlsKey(_) | NoblePrivateKey::TotpSecret(_) | NoblePrivateKey::FaucetPassphrase(_) => {
            return Err(CryptoError::EciesDecrypt("non-signing key cannot perform ECIES".into()));
        }
    };

    let derived_key = hkdf_derive(&shared_bytes)?;
    let dek_bytes = aes_decrypt(&derived_key, encrypted_key, key_nonce)?;
    let dek: [u8; 32] = dek_bytes.try_into().map_err(|v: Vec<u8>| {
        CryptoError::EciesDecrypt(format!("DEK must be 32 bytes, got {}", v.len()))
    })?;
    Ok(dek)
}

/// Encrypt a payload for one or more recipients using hybrid ECIES.
///
/// Generates a random 32-byte data encryption key (DEK), encrypts the payload
/// with AES-256-GCM, then encrypts the DEK for each recipient using ECIES.
#[tracing::instrument(skip(plaintext, recipients), fields(task = "ecies_encrypt"))]
pub fn ecies_encrypt(
    plaintext: &[u8],
    recipients: &[NoblePublicKey],
) -> Result<EciesPayload, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::EciesEncrypt(
            "at least one recipient required".into(),
        ));
    }

    tracing::debug!("ECIES: encrypted {} bytes for recipient", plaintext.len());

    // Generate random DEK
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    // Encrypt plaintext with DEK
    let (ciphertext, nonce) = aes_encrypt(&dek, plaintext)?;

    // Encrypt DEK for each recipient
    let mut recipient_envelopes = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        recipient_envelopes.push(encrypt_for_recipient(recipient, &dek)?);
    }

    Ok(EciesPayload {
        ciphertext,
        nonce,
        recipients: recipient_envelopes,
    })
}

/// Decrypt a payload as one of the recipients.
///
/// Finds the matching recipient envelope by comparing public keys,
/// decrypts the DEK, then decrypts the payload.
#[tracing::instrument(skip(payload, private_key), fields(task = "ecies_decrypt"))]
pub fn ecies_decrypt(
    payload: &EciesPayload,
    private_key: &NoblePrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    let our_pubkey = private_key.public_key();

    let envelope = payload
        .recipients
        .iter()
        .find(|r| r.recipient_pubkey == our_pubkey)
        .ok_or_else(|| CryptoError::EciesDecrypt("not a recipient of this payload".into()))?;

    let dek = decrypt_as_recipient(
        private_key,
        &envelope.ephemeral_pubkey,
        &envelope.encrypted_key,
        &envelope.key_nonce,
    )?;

    aes_decrypt(&dek, &payload.ciphertext, &payload.nonce)
}

// ── Single-recipient compact binary API (for metadata field encryption) ──

/// Encrypt plaintext for a single recipient, returning a compact binary payload.
///
/// Wire format: `nonce(12) || ciphertext(N+16) || ephemeral(33) || encrypted_key(48) || key_nonce(12)`
///
/// Total overhead: 121 bytes. With MAX_METADATA_VALUE_LEN=256, max plaintext is 134 bytes.
/// This format is used for per-field ECIES encryption in metadata slots.
#[tracing::instrument(skip(plaintext, recipient), fields(task = "ecies_encrypt_single"))]
pub fn encrypt_single(
    plaintext: &[u8],
    recipient: &NoblePublicKey,
) -> Result<Vec<u8>, CryptoError> {
    let payload = ecies_encrypt(plaintext, &[recipient.clone()])?;
    let env = &payload.recipients[0];

    // Validate expected sizes
    if env.ephemeral_pubkey.len() != 33 {
        return Err(CryptoError::EciesEncrypt(format!(
            "ephemeral pubkey must be 33 bytes, got {}",
            env.ephemeral_pubkey.len()
        )));
    }
    if env.encrypted_key.len() != 48 {
        return Err(CryptoError::EciesEncrypt(format!(
            "encrypted key must be 48 bytes (32+16 tag), got {}",
            env.encrypted_key.len()
        )));
    }

    let mut out = Vec::with_capacity(12 + payload.ciphertext.len() + 33 + 48 + 12);
    out.extend_from_slice(&payload.nonce);          // 12
    out.extend_from_slice(&payload.ciphertext);     // N+16
    out.extend_from_slice(&env.ephemeral_pubkey);   // 33
    out.extend_from_slice(&env.encrypted_key);      // 48
    out.extend_from_slice(&env.key_nonce);           // 12
    Ok(out)
}

/// Decrypt a compact single-recipient ECIES payload.
///
/// Wire format: `nonce(12) || ciphertext(N+16) || ephemeral(33) || encrypted_key(48) || key_nonce(12)`
///
/// Minimum payload size: 121 bytes (empty plaintext → 16 bytes ciphertext from GCM tag).
#[tracing::instrument(skip(payload, private_key), fields(task = "ecies_decrypt_single"))]
pub fn decrypt_single(
    payload: &[u8],
    private_key: &NoblePrivateKey,
) -> Result<Vec<u8>, CryptoError> {
    // Minimum: nonce(12) + tag(16) + ephemeral(33) + enc_key(48) + key_nonce(12) = 121
    if payload.len() < 121 {
        return Err(CryptoError::EciesDecrypt(format!(
            "payload too short ({} bytes, min 121)",
            payload.len()
        )));
    }

    let tail_len = 33 + 48 + 12; // ephemeral + encrypted_key + key_nonce = 93
    let ciphertext_end = payload.len() - tail_len;

    let nonce: [u8; 12] = payload[..12].try_into().expect("guaranteed by min size check");
    let ciphertext = &payload[12..ciphertext_end];
    let ephemeral_pubkey = &payload[ciphertext_end..ciphertext_end + 33];
    let encrypted_key = &payload[ciphertext_end + 33..ciphertext_end + 33 + 48];
    let key_nonce: [u8; 12] = payload[ciphertext_end + 33 + 48..].try_into().map_err(|_| {
        CryptoError::EciesDecrypt("invalid key_nonce length".into())
    })?;

    // Decrypt DEK
    let dek = decrypt_as_recipient(private_key, ephemeral_pubkey, encrypted_key, &key_nonce)?;

    // Decrypt ciphertext
    aes_decrypt(&dek, ciphertext, &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1;

    #[test]
    fn ecies_roundtrip_secp256k1() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        let plaintext = b"ipfs://QmTest123456789";
        let payload = ecies_encrypt(plaintext, &[pub_key]).unwrap();
        let decrypted = ecies_decrypt(&payload, &priv_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ecies_wrong_key_cannot_decrypt() {
        let (_, pk1) = secp256k1::generate_keypair();
        let (sk2, _) = secp256k1::generate_keypair();

        let pub_key1 = NoblePublicKey::Secp256k1(pk1);
        let priv_key2 = NoblePrivateKey::Secp256k1(sk2);

        let payload = ecies_encrypt(b"secret data", &[pub_key1]).unwrap();
        let result = ecies_decrypt(&payload, &priv_key2);
        assert!(result.is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn ecies_multiple_recipients() {
        let (sk1, pk1) = secp256k1::generate_keypair();
        let (sk2, pk2) = secp256k1::generate_keypair();

        let priv1 = NoblePrivateKey::Secp256k1(sk1);
        let priv2 = NoblePrivateKey::Secp256k1(sk2);
        let pub1 = NoblePublicKey::Secp256k1(pk1);
        let pub2 = NoblePublicKey::Secp256k1(pk2);

        let plaintext = b"shared document URL for multiple recipients";
        let payload = ecies_encrypt(plaintext, &[pub1, pub2]).unwrap();

        assert_eq!(payload.recipients.len(), 2);
        let dec1 = ecies_decrypt(&payload, &priv1).unwrap();
        let dec2 = ecies_decrypt(&payload, &priv2).unwrap();
        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);
    }

    #[test]
    fn ecies_zero_shared_secret_rejected() {
        let result = hkdf_derive(&[0u8; 32]);
        assert!(result.is_err(), "all-zero shared secret must be rejected");
    }

    #[test]
    fn ecies_payload_serde_roundtrip() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        let payload = ecies_encrypt(b"serde test", &[pub_key]).unwrap();
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: EciesPayload = serde_json::from_str(&json).unwrap();
        let decrypted = ecies_decrypt(&decoded, &priv_key).unwrap();
        assert_eq!(decrypted, b"serde test");
    }

    #[test]
    fn ecies_empty_payload() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        let payload = ecies_encrypt(b"", &[pub_key]).unwrap();
        let decrypted = ecies_decrypt(&payload, &priv_key).unwrap();
        assert!(decrypted.is_empty());
    }

    // ── Single-recipient compact binary tests ──

    #[test]
    fn single_roundtrip() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        let plaintext = b"user@example.com";
        let compact = encrypt_single(plaintext, &pub_key).unwrap();
        // 121 overhead + 16 plaintext bytes
        assert_eq!(compact.len(), 121 + plaintext.len());

        let decrypted = decrypt_single(&compact, &priv_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn single_max_plaintext_fits_256() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        // 134 bytes plaintext → 121 + 134 = 255 bytes total (fits in 256 value limit)
        let plaintext = vec![0x42u8; 134];
        let compact = encrypt_single(&plaintext, &pub_key).unwrap();
        assert_eq!(compact.len(), 255);

        let decrypted = decrypt_single(&compact, &priv_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn single_wrong_key_fails() {
        let (_, pk1) = secp256k1::generate_keypair();
        let (sk2, _) = secp256k1::generate_keypair();

        let pub_key1 = NoblePublicKey::Secp256k1(pk1);
        let priv_key2 = NoblePrivateKey::Secp256k1(sk2);

        let compact = encrypt_single(b"secret", &pub_key1).unwrap();
        assert!(decrypt_single(&compact, &priv_key2).is_err());
    }

    #[test]
    fn single_empty_plaintext() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = NoblePublicKey::Secp256k1(pk);

        let compact = encrypt_single(b"", &pub_key).unwrap();
        assert_eq!(compact.len(), 121); // overhead only, no plaintext bytes

        let decrypted = decrypt_single(&compact, &priv_key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn single_truncated_payload_rejected() {
        assert!(decrypt_single(&[0u8; 120], &NoblePrivateKey::Secp256k1([0u8; 32])).is_err());
    }
}
