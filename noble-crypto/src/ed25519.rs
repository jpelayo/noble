// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 digital signature operations.
//!
//! Uses `ed25519-dalek` v2 with strict verification mode (default),
//! which rejects small-order subgroup keys (GAP-M7).

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::CryptoError;

/// Ed25519 public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 secret key length in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Generate a new Ed25519 keypair using OS-level randomness.
///
/// Returns `(secret_key_bytes, public_key_bytes)`.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

/// Sign an arbitrary-length message with an Ed25519 secret key.
///
/// Returns the 64-byte signature.
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key_bytes: [u8; SECRET_KEY_LEN] = secret_key.try_into().map_err(|_| {
        CryptoError::InvalidKey(format!(
            "Ed25519 secret key must be {} bytes, got {}",
            SECRET_KEY_LEN,
            secret_key.len()
        ))
    })?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let sig = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a public key and message.
///
/// Uses strict verification (ed25519-dalek v2 default): rejects signatures
/// from small-order subgroup keys (GAP-M7).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let key_bytes: [u8; PUBLIC_KEY_LEN] = public_key.try_into().map_err(|_| {
        CryptoError::InvalidKey(format!(
            "Ed25519 public key must be {} bytes, got {}",
            PUBLIC_KEY_LEN,
            public_key.len()
        ))
    })?;

    let sig_bytes: [u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| {
        CryptoError::VerificationFailed(format!(
            "Ed25519 signature must be {} bytes, got {}",
            SIGNATURE_LEN,
            signature.len()
        ))
    })?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed25519 public key: {e}")))?;

    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message, &sig)
        .map_err(|e| CryptoError::VerificationFailed(format!("Ed25519: {e}")))
}

/// Batch-verify multiple Ed25519 signatures.
///
/// More efficient than verifying each signature individually.
/// Returns `Ok(())` if ALL signatures are valid, or an error if any fails.
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&[u8]],
    public_keys: &[&[u8]],
) -> Result<(), CryptoError> {
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return Err(CryptoError::VerificationFailed(
            "batch_verify: mismatched array lengths".to_string(),
        ));
    }

    if messages.is_empty() {
        return Ok(());
    }

    let mut verifying_keys = Vec::with_capacity(public_keys.len());
    let mut sigs = Vec::with_capacity(signatures.len());

    for (i, pk) in public_keys.iter().enumerate() {
        let key_bytes: [u8; PUBLIC_KEY_LEN] = (*pk).try_into().map_err(|_| {
            CryptoError::InvalidKey(format!(
                "batch item {i}: Ed25519 public key must be {} bytes",
                PUBLIC_KEY_LEN
            ))
        })?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("batch item {i}: {e}")))?;
        verifying_keys.push(vk);

        let sig_bytes: [u8; SIGNATURE_LEN] = signatures[i].try_into().map_err(|_| {
            CryptoError::VerificationFailed(format!(
                "batch item {i}: Ed25519 signature must be {} bytes",
                SIGNATURE_LEN
            ))
        })?;
        sigs.push(Signature::from_bytes(&sig_bytes));
    }

    ed25519_dalek::verify_batch(messages, &sigs, &verifying_keys)
        .map_err(|e| CryptoError::VerificationFailed(format!("batch verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let msg = b"NOBLE protocol test message";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_rejected() {
        let (sk, pk) = generate_keypair();
        let sig = sign(&sk, b"correct message").unwrap();
        assert!(verify(&pk, b"wrong message", &sig).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _pk) = generate_keypair();
        let (_, other_pk) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert!(verify(&other_pk, b"test", &sig).is_err());
    }

    #[test]
    fn signature_length() {
        let (sk, _) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
    }

    #[test]
    fn public_key_length() {
        let (_, pk) = generate_keypair();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn secret_key_length() {
        let (sk, _) = generate_keypair();
        assert_eq!(sk.len(), SECRET_KEY_LEN);
    }

    #[test]
    fn invalid_secret_key_length() {
        let result = sign(&[0u8; 16], b"test");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_public_key_length() {
        let result = verify(&[0u8; 16], b"test", &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_signature_length() {
        let (_, pk) = generate_keypair();
        let result = verify(&pk, b"test", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn batch_verify_valid() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        let (sk3, pk3) = generate_keypair();

        let msg1 = b"message one";
        let msg2 = b"message two";
        let msg3 = b"message three";

        let sig1 = sign(&sk1, msg1).unwrap();
        let sig2 = sign(&sk2, msg2).unwrap();
        let sig3 = sign(&sk3, msg3).unwrap();

        let messages: Vec<&[u8]> = vec![msg1, msg2, msg3];
        let signatures: Vec<&[u8]> = vec![&sig1, &sig2, &sig3];
        let public_keys: Vec<&[u8]> = vec![&pk1, &pk2, &pk3];

        assert!(batch_verify(&messages, &signatures, &public_keys).is_ok());
    }

    #[test]
    fn batch_verify_one_invalid() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let msg1 = b"message one";
        let msg2 = b"message two";

        let sig1 = sign(&sk1, msg1).unwrap();
        let sig2 = sign(&sk2, b"wrong message").unwrap(); // signed different message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures: Vec<&[u8]> = vec![&sig1, &sig2];
        let public_keys: Vec<&[u8]> = vec![&pk1, &pk2];

        assert!(batch_verify(&messages, &signatures, &public_keys).is_err());
    }

    #[test]
    fn batch_verify_empty() {
        assert!(batch_verify(&[], &[], &[]).is_ok());
    }

    #[test]
    fn batch_verify_mismatched_lengths() {
        assert!(batch_verify(&[b"a".as_slice()], &[], &[]).is_err());
    }

    #[test]
    fn deterministic_signatures() {
        // Ed25519 with ed25519-dalek is deterministic (RFC 6979-style)
        let (sk, _) = generate_keypair();
        let msg = b"determinism test";
        let sig1 = sign(&sk, msg).unwrap();
        let sig2 = sign(&sk, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_messages_different_signatures() {
        let (sk, _) = generate_keypair();
        let sig1 = sign(&sk, b"message A").unwrap();
        let sig2 = sign(&sk, b"message B").unwrap();
        assert_ne!(sig1, sig2);
    }
}
