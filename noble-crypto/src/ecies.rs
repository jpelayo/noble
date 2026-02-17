// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Hybrid ECIES encryption for NOBLE encrypted document locators.
//!
//! Supports both Ed25519 (via X25519 conversion) and secp256k1 recipients.
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
    /// Ephemeral public key used for ECDH (X25519 32 bytes or SEC1 33 bytes).
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

/// Convert an Ed25519 public key to X25519 for ECDH.
fn ed25519_pub_to_x25519(ed_pub: &[u8]) -> Result<x25519_dalek::PublicKey, CryptoError> {
    let key_bytes: [u8; 32] = ed_pub
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Ed25519 key must be 32 bytes".into()))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 key: {e}")))?;
    let montgomery = vk.to_montgomery();
    Ok(x25519_dalek::PublicKey::from(montgomery.to_bytes()))
}

/// Convert an Ed25519 secret key to X25519 for ECDH.
///
/// The Ed25519 seed is hashed with SHA-512; the first 32 bytes become the X25519 scalar.
/// Explicit clamping is applied before construction (M-clamp) as defense-in-depth.
fn ed25519_sk_to_x25519(ed_sk: &[u8]) -> Result<x25519_dalek::StaticSecret, CryptoError> {
    let sk_bytes: [u8; 32] = ed_sk
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Ed25519 secret key must be 32 bytes".into()))?;
    use sha2::Digest;
    let hash = sha2::Sha512::digest(sk_bytes);
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    // M-clamp: explicit X25519 clamping (belt-and-suspenders; x25519-dalek also clamps in DH)
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;
    Ok(x25519_dalek::StaticSecret::from(x25519_bytes))
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
        NoblePublicKey::Ed25519(pk_bytes) => {
            let x25519_pub = ed25519_pub_to_x25519(pk_bytes)?;
            let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

            let shared = ephemeral_secret.diffie_hellman(&x25519_pub);
            let derived_key = hkdf_derive(shared.as_bytes())?;
            let (encrypted_dek, key_nonce) = aes_encrypt(&derived_key, dek)?;

            Ok(EciesRecipient {
                recipient_pubkey: recipient.clone(),
                ephemeral_pubkey: ephemeral_public.as_bytes().to_vec(),
                encrypted_key: encrypted_dek,
                key_nonce,
            })
        }
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
        NoblePrivateKey::Ed25519(sk_bytes) => {
            let x25519_secret = ed25519_sk_to_x25519(sk_bytes)?;
            let eph_bytes: [u8; 32] = ephemeral_pubkey.try_into().map_err(|_| {
                CryptoError::EciesDecrypt("X25519 ephemeral key must be 32 bytes".into())
            })?;
            let eph_pub = x25519_dalek::PublicKey::from(eph_bytes);
            let shared = x25519_secret.diffie_hellman(&eph_pub);
            *shared.as_bytes()
        }
        NoblePrivateKey::Secp256k1(sk_bytes) => {
            let our_sk = k256::SecretKey::from_slice(sk_bytes)
                .map_err(|e| CryptoError::InvalidKey(format!("secp256k1: {e}")))?;
            let eph_pk = k256::PublicKey::from_sec1_bytes(ephemeral_pubkey)
                .map_err(|e| CryptoError::EciesDecrypt(format!("ephemeral key: {e}")))?;

            // Compute ECDH: shared = eph_pk * our_scalar
            let shared = k256::ecdh::diffie_hellman(our_sk.to_nonzero_scalar(), eph_pk.as_affine());
            let bytes: [u8; 32] = shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .expect("secp256k1 shared secret is 32 bytes");
            bytes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed25519, secp256k1};

    #[test]
    fn ed25519_to_x25519_key_conversion() {
        // Verify that Ed25519 → X25519 conversion produces consistent keypairs:
        // the public key derived from the converted secret matches the converted public key.
        let (sk, pk) = ed25519::generate_keypair();
        let x25519_pub = ed25519_pub_to_x25519(&pk).unwrap();
        let x25519_sec = ed25519_sk_to_x25519(&sk).unwrap();
        let derived_pub = x25519_dalek::PublicKey::from(&x25519_sec);
        assert_eq!(x25519_pub.as_bytes(), derived_pub.as_bytes());
    }

    #[test]
    fn ecies_roundtrip_ed25519() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let plaintext = b"https://example.com/document.pdf";
        let payload = ecies_encrypt(plaintext, &[pub_key]).unwrap();
        let decrypted = ecies_decrypt(&payload, &priv_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

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
        let (_, pk1) = ed25519::generate_keypair();
        let (sk2, _) = ed25519::generate_keypair();

        let pub_key1 = NoblePublicKey::Ed25519(pk1);
        let priv_key2 = NoblePrivateKey::Ed25519(sk2);

        let payload = ecies_encrypt(b"secret data", &[pub_key1]).unwrap();
        let result = ecies_decrypt(&payload, &priv_key2);
        assert!(result.is_err(), "wrong key must not decrypt");
    }

    #[test]
    fn ecies_multiple_recipients() {
        let (sk1, pk1) = ed25519::generate_keypair();
        let (sk2, pk2) = secp256k1::generate_keypair();

        let priv1 = NoblePrivateKey::Ed25519(sk1);
        let priv2 = NoblePrivateKey::Secp256k1(sk2);
        let pub1 = NoblePublicKey::Ed25519(pk1);
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
        // H-ecies0: all-zero shared secret must be rejected
        let result = hkdf_derive(&[0u8; 32]);
        assert!(result.is_err(), "all-zero shared secret must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("all-zero"),
            "error should mention all-zero: {err}"
        );
    }

    #[test]
    fn ecies_payload_serde_roundtrip() {
        // H-serde: EciesPayload and EciesRecipient are serializable
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let payload = ecies_encrypt(b"serde test", &[pub_key]).unwrap();
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: EciesPayload = serde_json::from_str(&json).unwrap();
        let decrypted = ecies_decrypt(&decoded, &priv_key).unwrap();
        assert_eq!(decrypted, b"serde test");
    }

    #[test]
    fn ecies_empty_payload() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let payload = ecies_encrypt(b"", &[pub_key]).unwrap();
        let decrypted = ecies_decrypt(&payload, &priv_key).unwrap();
        assert!(decrypted.is_empty());
    }
}
