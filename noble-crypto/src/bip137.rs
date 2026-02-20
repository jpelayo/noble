// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! BIP-137 Bitcoin message signing for NOBLE protocol compatibility.
//!
//! Allows Bitcoin wallet holders to sign NOBLE transactions using the
//! standard Bitcoin Signed Message format (double-SHA256 with magic prefix).
//! The recoverable signature format enables public key recovery, eliminating
//! the need to transmit the full public key separately.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CryptoError;

/// BIP-137 recoverable signature length: 1 byte recovery + 32 bytes r + 32 bytes s.
pub const BIP137_SIG_LEN: usize = 65;

/// Bitcoin message signing magic prefix.
const BITCOIN_MSG_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Encode an integer as a Bitcoin varint (CompactSize).
///
/// - 0..=0xFC: 1 byte
/// - 0xFD..=0xFFFF: 0xFD + 2 bytes LE
/// - 0x10000..=0xFFFFFFFF: 0xFE + 4 bytes LE
/// - 0x100000000..: 0xFF + 8 bytes LE
pub fn encode_varint(n: usize) -> Vec<u8> {
    if n <= 0xFC {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut buf = vec![0xFD];
        buf.extend_from_slice(&(n as u16).to_le_bytes());
        buf
    } else if n <= 0xFFFF_FFFF {
        let mut buf = vec![0xFE];
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xFF];
        buf.extend_from_slice(&(n as u64).to_le_bytes());
        buf
    }
}

/// Compute the Bitcoin double-SHA256 message hash for BIP-137.
///
/// Format: `SHA256(SHA256(magic_prefix || varint(msg.len()) || msg))`
pub fn bip137_message_hash(message: &str) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(BITCOIN_MSG_PREFIX);
    preimage.extend_from_slice(&encode_varint(message.len()));
    preimage.extend_from_slice(message.as_bytes());

    let first = Sha256::digest(&preimage);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Sign a message using BIP-137 Bitcoin Signed Message format.
///
/// Returns a 65-byte recoverable signature: `[recovery_id + 27 + 4] || r || s`.
/// The `+27` is the Bitcoin base offset, and `+4` indicates a compressed public key.
pub fn sign_bip137(secret_key: &[u8], message: &str) -> Result<[u8; 65], CryptoError> {
    let signing_key = SigningKey::from_slice(secret_key)
        .map_err(|e| CryptoError::InvalidKey(format!("BIP-137 secret key: {e}")))?;

    let hash = bip137_message_hash(message);

    let (sig, recovery_id): (Signature, RecoveryId) =
        signing_key
            .sign_prehash_recoverable(&hash)
            .map_err(|e| CryptoError::SigningFailed(format!("BIP-137 sign: {e}")))?;

    let mut result = [0u8; 65];
    // First byte: recovery_id + 27 (base) + 4 (compressed key flag)
    result[0] = recovery_id.to_byte() + 27 + 4;
    let sig_bytes = sig.to_bytes();
    result[1..33].copy_from_slice(&sig_bytes[..32]); // r
    result[33..65].copy_from_slice(&sig_bytes[32..]); // s
    Ok(result)
}

/// Verify a BIP-137 recoverable signature and return the 33-byte compressed public key.
///
/// Parses the 65-byte signature, recovers the public key from the prehash,
/// and returns the compressed SEC1-encoded public key.
pub fn verify_bip137(sig: &[u8], message: &str) -> Result<Vec<u8>, CryptoError> {
    if sig.len() != BIP137_SIG_LEN {
        return Err(CryptoError::VerificationFailed(format!(
            "BIP-137 signature must be {} bytes, got {}",
            BIP137_SIG_LEN,
            sig.len()
        )));
    }

    let header = sig[0];
    if !(31..=34).contains(&header) {
        return Err(CryptoError::VerificationFailed(format!(
            "BIP-137 invalid header byte: {header:#04x} (expected 31..=34)"
        )));
    }

    let recovery_id_byte = header - 27 - 4;
    let recovery_id = RecoveryId::try_from(recovery_id_byte).map_err(|e| {
        CryptoError::VerificationFailed(format!("BIP-137 invalid recovery id: {e}"))
    })?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig[1..33]); // r
    sig_bytes[32..].copy_from_slice(&sig[33..65]); // s

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| CryptoError::VerificationFailed(format!("BIP-137 signature parse: {e}")))?;

    let hash = bip137_message_hash(message);

    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
        .map_err(|e| CryptoError::VerificationFailed(format!("BIP-137 recovery: {e}")))?;

    Ok(verifying_key.to_sec1_bytes().to_vec())
}

/// Build the canonical message string for a notarization transaction.
///
/// Format: `"NOBLE:notarize:{checksum}:{timestamp}:{fee}:{version}"`
pub fn notarization_message(checksum: &str, timestamp: u64, fee: u64, version: u16) -> String {
    format!("NOBLE:notarize:{checksum}:{timestamp}:{fee}:{version}")
}

/// Build the canonical message string for a transfer transaction.
///
/// Format: `"NOBLE:transfer:{recipient}:{amount}:{timestamp}:{fee}:{version}"`
pub fn transfer_message(
    recipient: &str,
    amount: u64,
    timestamp: u64,
    fee: u64,
    version: u16,
) -> String {
    format!("NOBLE:transfer:{recipient}:{amount}:{timestamp}:{fee}:{version}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::generate_keypair;

    #[test]
    fn message_hash_deterministic() {
        let h1 = bip137_message_hash("Hello NOBLE");
        let h2 = bip137_message_hash("Hello NOBLE");
        assert_eq!(h1, h2);

        // Different message produces different hash
        let h3 = bip137_message_hash("Hello Bitcoin");
        assert_ne!(h1, h3);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, _) = generate_keypair();
        let message = "NOBLE:notarize:abcdef1234567890:1700000000:1000:1";

        let sig = sign_bip137(&sk, message).unwrap();
        assert_eq!(sig.len(), 65);

        // Header byte should be in range 31..=34
        assert!(sig[0] >= 31 && sig[0] <= 34, "header: {}", sig[0]);

        // Recover public key
        let recovered_pk = verify_bip137(&sig, message).unwrap();
        assert_eq!(recovered_pk.len(), 33);
        assert!(recovered_pk[0] == 0x02 || recovered_pk[0] == 0x03);

        // Recovered key should match the original
        let signing_key = SigningKey::from_slice(&sk).unwrap();
        let expected_pk = signing_key.verifying_key().to_sec1_bytes().to_vec();
        assert_eq!(recovered_pk, expected_pk);
    }

    #[test]
    fn invalid_signature_rejected() {
        let bad_sig = [0u8; 65];
        let result = verify_bip137(&bad_sig, "test message");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_length_signature_rejected() {
        let result = verify_bip137(&[0u8; 32], "test message");
        assert!(result.is_err());
    }

    #[test]
    fn varint_encoding() {
        // Single byte
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(1), vec![1]);
        assert_eq!(encode_varint(252), vec![252]);

        // Two-byte
        assert_eq!(encode_varint(253), vec![0xFD, 253, 0]);
        assert_eq!(encode_varint(0xFFFF), vec![0xFD, 0xFF, 0xFF]);

        // Four-byte
        assert_eq!(encode_varint(0x10000), vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn notarization_message_format() {
        let msg = notarization_message("abcdef1234", 1700000000, 1000, 1);
        assert_eq!(msg, "NOBLE:notarize:abcdef1234:1700000000:1000:1");
    }

    #[test]
    fn transfer_message_format() {
        let msg = transfer_message("recipient_hex", 50000, 1700000000, 1000, 1);
        assert_eq!(msg, "NOBLE:transfer:recipient_hex:50000:1700000000:1000:1");
    }
}
