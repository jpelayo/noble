// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! SHA-256 hashing and the `Hash256` newtype for 32-byte hashes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use noble_codec::NobleCbor;

use crate::error::CryptoError;

/// A 32-byte SHA-256 hash value.
///
/// This is the fundamental hash type used throughout the NOBLE protocol
/// for transaction IDs, block hashes, Merkle roots, and checksums.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash256(#[serde(with = "serde_hash256")] pub [u8; 32]);

/// Custom serde for Hash256: serialize as CBOR byte string instead of array of integers.
mod serde_hash256 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = [u8; 32];

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "32 bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
                v.try_into()
                    .map_err(|_| E::invalid_length(v.len(), &"32 bytes"))
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl Hash256 {
    /// The all-zero hash, used as a sentinel value (e.g., genesis block's prev_block_hash).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create a Hash256 from a 32-byte array.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the underlying bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create a Hash256 from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes =
            hex::decode(s).map_err(|e| CryptoError::HashError(format!("invalid hex: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            CryptoError::HashError(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", hex::encode(self.0))
    }
}

impl FromStr for Hash256 {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Compute the SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Hash256(result.into())
}

/// Compute the double SHA-256 hash (SHA-256 of SHA-256) of arbitrary data.
///
/// Used for transaction IDs, following the Bitcoin convention of using
/// double-hashing to prevent length-extension attacks.
pub fn double_sha256(data: &[u8]) -> Hash256 {
    tracing::trace!("sha256: hashing {} bytes", data.len());
    let first = sha256(data);
    sha256(&first.0)
}

/// Compute the SHA-256 hash of a type's canonical CBOR encoding.
///
/// This is the standard way to hash protocol objects in NOBLE.
pub fn canonical_hash<T: NobleCbor>(value: &T) -> Result<Hash256, CryptoError> {
    let bytes = value
        .canonical_bytes()
        .map_err(|e| CryptoError::HashError(e.to_string()))?;
    Ok(sha256(&bytes))
}

/// Compute the double SHA-256 hash of a type's canonical CBOR encoding.
///
/// Used for computing transaction IDs and other critical identifiers.
pub fn canonical_double_hash<T: NobleCbor>(value: &T) -> Result<Hash256, CryptoError> {
    let bytes = value
        .canonical_bytes()
        .map_err(|e| CryptoError::HashError(e.to_string()))?;
    Ok(double_sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SHA-256 test vectors (NIST CAVP / well-known) ---

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(
            hash.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256(b"abc");
        assert_eq!(
            hash.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_448bit_message() {
        // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hash.to_string(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_noble() {
        // Verify SHA-256 of "NOBLE" is deterministic
        let h1 = sha256(b"NOBLE");
        let h2 = sha256(b"NOBLE");
        assert_eq!(h1, h2);
        // Different input produces different hash
        assert_ne!(sha256(b"NOBLE"), sha256(b"noble"));
    }

    #[test]
    fn sha256_single_zero_byte() {
        // SHA-256("\x00") = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
        let hash = sha256(&[0u8]);
        assert_eq!(
            hash.to_string(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    // --- Double SHA-256 ---

    #[test]
    fn double_sha256_empty() {
        // Bitcoin uses double SHA-256. SHA-256(SHA-256("")) is well-known:
        // 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let hash = double_sha256(b"");
        assert_eq!(
            hash.to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn double_sha256_differs_from_single() {
        let single = sha256(b"test");
        let double = double_sha256(b"test");
        assert_ne!(single, double);
        // Double hash equals hashing the single hash
        assert_eq!(double, sha256(single.as_bytes()));
    }

    // --- Hash256 type ---

    #[test]
    fn hash256_zero() {
        assert_eq!(Hash256::ZERO, Hash256::from_bytes([0u8; 32]));
        assert_eq!(
            Hash256::ZERO.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn hash256_display_fromstr_roundtrip() {
        let hash = sha256(b"roundtrip test");
        let hex_str = hash.to_string();
        let parsed: Hash256 = hex_str.parse().unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn hash256_from_hex_valid() {
        let hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let hash = Hash256::from_hex(hex).unwrap();
        assert_eq!(hash.to_string(), hex);
    }

    #[test]
    fn hash256_from_hex_wrong_length() {
        assert!(Hash256::from_hex("abcd").is_err());
        assert!(Hash256::from_hex("").is_err());
    }

    #[test]
    fn hash256_from_hex_invalid_chars() {
        let bad = "zzzz6bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(Hash256::from_hex(bad).is_err());
    }

    #[test]
    fn hash256_ordering() {
        let a = Hash256::from_bytes([0u8; 32]);
        let b = Hash256::from_bytes([1u8; 32]);
        assert!(a < b);
    }

    #[test]
    fn hash256_copy_semantics() {
        let h = sha256(b"copy test");
        let h2 = h; // Copy
        assert_eq!(h, h2);
    }

    // --- Hash256 CBOR serialization ---

    #[test]
    fn hash256_cbor_roundtrip() {
        let hash = sha256(b"cbor test");
        let bytes = hash.to_cbor().unwrap();
        let decoded = Hash256::from_cbor(&bytes).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn hash256_cbor_uses_byte_string() {
        // Hash256 should serialize as CBOR byte string (major type 2), not array
        let hash = Hash256::ZERO;
        let bytes = hash.to_cbor().unwrap();
        // CBOR byte string of 32 bytes: 0x58 0x20 (major type 2, additional info 24, length 32)
        assert_eq!(bytes[0], 0x58, "should be CBOR byte string header");
        assert_eq!(bytes[1], 0x20, "should be length 32");
        assert_eq!(bytes.len(), 34, "header(2) + data(32)");
    }

    // --- Canonical hash helpers ---

    #[test]
    fn canonical_hash_deterministic() {
        use serde::Deserialize;

        #[derive(Serialize, Deserialize)]
        struct TestStruct {
            z: u32,
            a: u32,
        }

        let val = TestStruct { z: 1, a: 2 };
        let h1 = canonical_hash(&val).unwrap();
        let h2 = canonical_hash(&val).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_double_hash_differs_from_single() {
        use serde::Deserialize;

        #[derive(Serialize, Deserialize)]
        struct TestStruct {
            x: u32,
        }

        let val = TestStruct { x: 42 };
        let single = canonical_hash(&val).unwrap();
        let double = canonical_double_hash(&val).unwrap();
        assert_ne!(single, double);
    }
}
