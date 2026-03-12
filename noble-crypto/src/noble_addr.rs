// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Human-readable Noble native address encoding.
//!
//! Noble native public keys are encoded as bech32/bech32m strings with the `nbl` HRP:
//!
//! | Key type  | Witness version | Prefix   | Encoding |
//! |-----------|----------------|----------|----------|
//! | Ed25519   | v0             | `nbl1q…` | bech32   |
//! | secp256k1 | v1             | `nbl1p…` | bech32m  |
//!
//! Wire format and storage are unaffected — this is purely the display layer.

use crate::keys::NoblePublicKey;
use crate::schemes::{SCHEME_ED25519, SCHEME_SECP256K1};

/// Human-readable part for Noble native addresses.
const HRP: &str = "nbl";

/// Encode a `NoblePublicKey` as a human-readable `nbl1…` address.
///
/// - Ed25519 (32 bytes) → witness v0 → `nbl1q…`
/// - secp256k1 (33 bytes) → witness v1 → `nbl1p…`
pub fn encode(key: &NoblePublicKey) -> String {
    let hrp = bech32::Hrp::parse(HRP).expect("valid HRP");
    let (version, program) = match key {
        NoblePublicKey::Ed25519(bytes) => (0u8, bytes.as_slice()),
        NoblePublicKey::Secp256k1(bytes) => (1u8, bytes.as_slice()),
    };
    let ver = bech32::Fe32::try_from(version).expect("valid witness version");
    bech32::segwit::encode(hrp, ver, program)
        .expect("valid noble address encoding")
}

/// Decode a `nbl1…` address back to a `NoblePublicKey`.
///
/// Returns an error if the HRP is not `nbl`, the witness version is unrecognized,
/// or the program length doesn't match the expected key type.
pub fn decode(addr: &str) -> Result<NoblePublicKey, DecodeError> {
    let (hrp, version, program) = bech32::segwit::decode(addr)
        .map_err(|e| DecodeError::Bech32(e.to_string()))?;

    let expected_hrp = bech32::Hrp::parse(HRP).expect("valid HRP");
    if hrp != expected_hrp {
        return Err(DecodeError::WrongHrp(hrp.to_string()));
    }

    let ver: u8 = version.to_u8();
    match ver {
        0 => {
            if program.len() != 32 {
                return Err(DecodeError::InvalidLength {
                    version: ver,
                    expected: 32,
                    got: program.len(),
                });
            }
            Ok(NoblePublicKey::Ed25519(program))
        }
        1 => {
            if program.len() != 33 {
                return Err(DecodeError::InvalidLength {
                    version: ver,
                    expected: 33,
                    got: program.len(),
                });
            }
            Ok(NoblePublicKey::Secp256k1(program))
        }
        _ => Err(DecodeError::UnknownVersion(ver)),
    }
}

/// Check whether a string looks like a Noble native address (`nbl1…`).
pub fn is_noble_address(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("nbl1")
}

/// Encode raw wire bytes (scheme_id + key_bytes) to a Noble address.
///
/// Convenience wrapper that first parses wire bytes into a `NoblePublicKey`,
/// then encodes. Returns `None` if the wire bytes aren't a valid Noble key.
pub fn encode_wire_bytes(wire: &[u8]) -> Option<String> {
    if wire.is_empty() {
        return None;
    }
    match wire[0] {
        SCHEME_ED25519 | SCHEME_SECP256K1 => {
            let key = NoblePublicKey::from_wire_bytes(wire).ok()?;
            Some(encode(&key))
        }
        _ => None,
    }
}

/// Errors from Noble address decoding.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    #[error("bech32 decode failed: {0}")]
    Bech32(String),
    #[error("wrong HRP: expected 'nbl', got '{0}'")]
    WrongHrp(String),
    #[error("unknown witness version: {0}")]
    UnknownVersion(u8),
    #[error("invalid program length for v{version}: expected {expected}, got {got}")]
    InvalidLength {
        version: u8,
        expected: usize,
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519;
    use crate::secp256k1;

    #[test]
    fn ed25519_roundtrip() {
        let (_, pk_bytes) = ed25519::generate_keypair();
        let key = NoblePublicKey::Ed25519(pk_bytes);
        let addr = encode(&key);
        assert!(addr.starts_with("nbl1q"), "Ed25519 should start with nbl1q, got: {addr}");
        let decoded = decode(&addr).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn secp256k1_roundtrip() {
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let key = NoblePublicKey::Secp256k1(pk_bytes);
        let addr = encode(&key);
        assert!(addr.starts_with("nbl1p"), "secp256k1 should start with nbl1p, got: {addr}");
        let decoded = decode(&addr).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn is_noble_address_detection() {
        assert!(is_noble_address("nbl1qsomething"));
        assert!(is_noble_address("NBL1Qsomething"));
        assert!(!is_noble_address("bc1qsomething"));
        assert!(!is_noble_address("01abcdef"));
    }

    #[test]
    fn wrong_hrp_rejected() {
        // Encode a real address, then tamper the HRP
        let (_, pk_bytes) = ed25519::generate_keypair();
        let key = NoblePublicKey::Ed25519(pk_bytes);
        let addr = encode(&key);
        let tampered = addr.replacen("nbl", "abc", 1);
        assert!(decode(&tampered).is_err());
    }

    #[test]
    fn encode_wire_bytes_ed25519() {
        let (_, pk_bytes) = ed25519::generate_keypair();
        let key = NoblePublicKey::Ed25519(pk_bytes);
        let wire = key.to_wire_bytes();
        let addr = encode_wire_bytes(&wire).unwrap();
        assert!(addr.starts_with("nbl1q"));
        let decoded = decode(&addr).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn encode_wire_bytes_bitcoin_returns_none() {
        // Bitcoin prefix should not encode as nbl
        let mut wire = vec![0x80];
        wire.extend_from_slice(&[0xab; 20]);
        assert!(encode_wire_bytes(&wire).is_none());
    }

    #[test]
    fn case_insensitive_decode() {
        let (_, pk_bytes) = ed25519::generate_keypair();
        let key = NoblePublicKey::Ed25519(pk_bytes);
        let addr = encode(&key).to_uppercase();
        let decoded = decode(&addr).unwrap();
        assert_eq!(key, decoded);
    }
}
