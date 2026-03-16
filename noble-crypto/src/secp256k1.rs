// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! secp256k1 ECDSA digital signature operations.
//!
//! Uses `k256` (pure Rust, GAP-L8) with low-S normalization (GAP-H1/BIP-62)
//! to prevent transaction malleability.

use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::CryptoError;

/// Compressed secp256k1 public key length in bytes (0x02/0x03 prefix + 32 bytes).
pub const PUBLIC_KEY_LEN: usize = 33;

/// secp256k1 secret key length in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// secp256k1 ECDSA signature length in bytes (r + s, each 32 bytes).
pub const SIGNATURE_LEN: usize = 64;

/// Generate a new secp256k1 keypair using OS-level randomness.
///
/// Returns `(secret_key_bytes, compressed_public_key_bytes)`.
/// The public key is 33 bytes: a 0x02 or 0x03 prefix followed by the 32-byte X coordinate.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_sec1_bytes().to_vec(),
    )
}

/// Derive a secp256k1 keypair from a 32-byte secret key.
///
/// Returns `(secret_key_bytes, compressed_public_key_bytes)`.
pub fn keypair_from_secret(secret: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let signing_key = SigningKey::from_slice(secret)
        .map_err(|e| CryptoError::InvalidKey(format!("secp256k1 secret: {e}")))?;
    let verifying_key = signing_key.verifying_key();
    Ok((
        signing_key.to_bytes().to_vec(),
        verifying_key.to_sec1_bytes().to_vec(),
    ))
}

/// Sign an arbitrary-length message with a secp256k1 secret key.
///
/// The message is internally hashed (SHA-256) before signing, per standard ECDSA.
/// Returns the 64-byte signature with low-S normalization applied (GAP-H1).
/// The S value is guaranteed to be in the lower half of the curve order,
/// preventing transaction malleability (BIP-62).
#[tracing::instrument(skip(secret_key, message), fields(task = "crypto_sign"))]
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signing_key = SigningKey::from_slice(secret_key)
        .map_err(|e| CryptoError::InvalidKey(format!("secp256k1 secret key: {e}")))?;

    let sig: Signature = signing_key.sign(message);

    // GAP-H1: normalize to low-S
    let normalized = sig.normalize_s().unwrap_or(sig);
    Ok(normalized.to_bytes().to_vec())
}

/// Verify a secp256k1 ECDSA signature against a public key and message.
///
/// Rejects high-S signatures (GAP-H1): the S value must be in the lower half
/// of the curve order to prevent malleability.
#[tracing::instrument(skip(public_key, message, signature), fields(task = "crypto_verify"))]
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| CryptoError::InvalidKey(format!("secp256k1 public key: {e}")))?;

    let sig = Signature::from_slice(signature)
        .map_err(|e| CryptoError::VerificationFailed(format!("secp256k1 signature: {e}")))?;

    // GAP-H1: reject high-S signatures
    if sig.normalize_s().is_some() {
        return Err(CryptoError::VerificationFailed(
            "secp256k1: high-S signature rejected (BIP-62)".to_string(),
        ));
    }

    verifying_key
        .verify(message, &sig)
        .map_err(|e| CryptoError::VerificationFailed(format!("secp256k1: {e}")))?;

    tracing::trace!("secp256k1 signature verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::bigint::Encoding;
    use k256::elliptic_curve::Curve;

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let msg = b"NOBLE secp256k1 test message";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_rejected() {
        let (sk, pk) = generate_keypair();
        let sig = sign(&sk, b"correct").unwrap();
        assert!(verify(&pk, b"wrong", &sig).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _) = generate_keypair();
        let (_, other_pk) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert!(verify(&other_pk, b"test", &sig).is_err());
    }

    #[test]
    fn compressed_public_key_format() {
        let (_, pk) = generate_keypair();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn secret_key_length() {
        let (sk, _) = generate_keypair();
        assert_eq!(sk.len(), SECRET_KEY_LEN);
    }

    #[test]
    fn signature_length() {
        let (sk, _) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
    }

    #[test]
    fn signature_is_low_s() {
        let (sk, _) = generate_keypair();
        let half_order = k256::Secp256k1::ORDER.shr_vartime(1);

        for i in 0..50 {
            let msg = format!("low-s test message {i}");
            let sig_bytes = sign(&sk, msg.as_bytes()).unwrap();
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            let (_, s) = sig.split_bytes();
            let s_uint = k256::U256::from_be_slice(&s);
            assert!(s_uint <= half_order, "signature {i} has high-S value");
        }
    }

    #[test]
    fn high_s_signature_rejected() {
        let (sk, pk) = generate_keypair();
        let msg = b"high-s test";
        let sig_bytes = sign(&sk, msg).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();

        // Our sig is low-S. Create the high-S variant by negating S (S' = N - S).
        let (r, s) = sig.split_bytes();
        let s_uint = k256::U256::from_be_slice(&s);
        let order = k256::Secp256k1::ORDER;
        let high_s = order.wrapping_sub(&s_uint);
        let mut high_s_bytes = [0u8; 64];
        high_s_bytes[..32].copy_from_slice(&r);
        high_s_bytes[32..].copy_from_slice(&high_s.to_be_bytes());

        let result = verify(&pk, msg, &high_s_bytes);
        assert!(result.is_err(), "high-S signature must be rejected");
    }

    #[test]
    fn invalid_secret_key() {
        let result = sign(&[0u8; 32], b"test");
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
}
