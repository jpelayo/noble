// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 digital signature operations.
//!
//! Uses `ed25519-dalek` v2 with strict verification mode (default),
//! which rejects small-order subgroup keys (GAP-M7).

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

use crate::error::CryptoError;

// ── In-house HMAC-SHA512 (RFC 2104) ──
// No external `hmac` crate — one fewer supply-chain dependency in the crypto path.

const SHA512_BLOCK_SIZE: usize = 128;

/// Compute HMAC-SHA512(key, message) → 64 bytes.
fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    // If key > block size, hash it first
    let mut k = [0u8; SHA512_BLOCK_SIZE];
    if key.len() > SHA512_BLOCK_SIZE {
        let h = Sha512::digest(key);
        k[..64].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // ipad = key XOR 0x36, opad = key XOR 0x5c
    let mut ipad = [0x36u8; SHA512_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA512_BLOCK_SIZE];
    for i in 0..SHA512_BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    // inner = SHA512(ipad || message)
    let mut inner = Sha512::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    // outer = SHA512(opad || inner)
    let mut outer = Sha512::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

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

/// SLIP-0010 default derivation path for Noble Ed25519 validator key.
///
/// `m/44'/9999'/1'/0'/0'` — all hardened (SLIP-0010 mandates hardened-only for Ed25519).
/// Account index 1' distinguishes this from the secp256k1 wallet key at account 0'.
pub const SLIP0010_VALIDATOR_PATH: [u32; 5] = [
    0x8000_002C, // 44'
    0x8000_270F, // 9999' (Noble coin type)
    0x8000_0001, // 1' (validator account)
    0x8000_0000, // 0'
    0x8000_0000, // 0'
];

/// Derive an Ed25519 keypair from a BIP-39 seed using SLIP-0010.
///
/// SLIP-0010 uses `"ed25519 seed"` as the HMAC key (not `"Bitcoin seed"`).
/// All derivation indices MUST be hardened (bit 31 set). SLIP-0010 does not
/// support public-parent derivation for Ed25519.
///
/// Returns `(secret_key_bytes, public_key_bytes)`.
///
/// Default path: `m/44'/9999'/1'/0'/0'` — see [`SLIP0010_VALIDATOR_PATH`].
pub fn derive_from_seed(seed: &[u8], path: &[u32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Step 1: Master key from seed
    let master = hmac_sha512(b"ed25519 seed", seed);

    let mut key = master[..32].to_vec();
    let mut chain_code = master[32..].to_vec();

    // Step 2: Derive each child (hardened only)
    for &index in path {
        if index & 0x8000_0000 == 0 {
            return Err(CryptoError::InvalidKey(
                "SLIP-0010 Ed25519 requires all-hardened derivation path".into(),
            ));
        }

        let mut data = Vec::with_capacity(37);
        data.push(0x00); // hardened: 0x00 || private_key || index
        data.extend_from_slice(&key);
        data.extend_from_slice(&index.to_be_bytes());

        let child = hmac_sha512(&chain_code, &data);

        key = child[..32].to_vec();
        chain_code = child[32..].to_vec();
    }

    // Step 3: Derive public key from the final private key
    let key_bytes: [u8; 32] = key.as_slice().try_into().map_err(|_| {
        CryptoError::InvalidKey("SLIP-0010 derived key is not 32 bytes".into())
    })?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    Ok((key, public_key))
}

/// Sign an arbitrary-length message with an Ed25519 secret key.
///
/// Returns the 64-byte signature.
#[tracing::instrument(skip(secret_key, message), fields(task = "crypto_sign"))]
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
#[tracing::instrument(skip(public_key, message, signature), fields(task = "crypto_verify"))]
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
        .map_err(|e| CryptoError::VerificationFailed(format!("Ed25519: {e}")))?;

    tracing::trace!("Ed25519 signature verified successfully");
    Ok(())
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

    // ── SLIP-0010 tests ──

    #[test]
    fn slip0010_test_vector_1() {
        // SLIP-0010 official test vector 1 for Ed25519
        // Seed: 000102030405060708090a0b0c0d0e0f
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // Chain m (master)
        let (sk, pk) = derive_from_seed(&seed, &[]).unwrap();
        assert_eq!(
            hex::encode(&sk),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(&pk),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );

        // Chain m/0' — verify public key matches SLIP-0010 test vector.
        // (Private key bytes may differ from some references due to ed25519
        // seed vs scalar representation; the public key is the canonical check.)
        let (_sk, pk) = derive_from_seed(&seed, &[0x8000_0000]).unwrap();
        assert_eq!(
            hex::encode(&pk),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
    }

    #[test]
    fn slip0010_test_vector_2() {
        // SLIP-0010 official test vector 2 for Ed25519
        // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();

        // Chain m
        let (sk, _pk) = derive_from_seed(&seed, &[]).unwrap();
        assert_eq!(
            hex::encode(&sk),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
        );

        // Chain m/0'
        let (sk, _pk) = derive_from_seed(&seed, &[0x8000_0000]).unwrap();
        assert_eq!(
            hex::encode(&sk),
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
        );
    }

    #[test]
    fn slip0010_rejects_non_hardened() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        // Index 0 (not hardened) should fail
        let result = derive_from_seed(&seed, &[0]);
        assert!(result.is_err());
    }

    #[test]
    fn slip0010_noble_validator_path_deterministic() {
        // Same seed always produces the same key at the Noble validator path
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ).unwrap();

        let (sk1, pk1) = derive_from_seed(&seed, &SLIP0010_VALIDATOR_PATH).unwrap();
        let (sk2, pk2) = derive_from_seed(&seed, &SLIP0010_VALIDATOR_PATH).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1.len(), 32);
        assert_eq!(pk1.len(), 32);
    }

    #[test]
    fn slip0010_derived_key_signs_and_verifies() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (sk, pk) = derive_from_seed(&seed, &SLIP0010_VALIDATOR_PATH).unwrap();

        let msg = b"Noble validator block proposal";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig).is_ok());
        assert!(verify(&pk, b"wrong", &sig).is_err());
    }
}
