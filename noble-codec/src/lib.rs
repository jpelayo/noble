// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! CBOR serialization traits and canonical encoding for the NOBLE protocol.
//!
//! This crate provides the [`NobleCbor`] trait for serializing and deserializing
//! NOBLE protocol types using CBOR (RFC 8949), with support for deterministic
//! canonical encoding as required for cryptographic hashing.
//!
//! # Canonical Encoding
//!
//! Canonical CBOR follows RFC 8949 Section 4.2.1 (Core Deterministic Encoding):
//! - Map keys are sorted by their encoded byte representation (length-first,
//!   then lexicographic)
//! - Integers use the shortest possible encoding
//! - Definite-length encoding for all containers
//!
//! # Usage
//!
//! Any type implementing `serde::Serialize + serde::de::DeserializeOwned`
//! automatically gets a [`NobleCbor`] implementation via the blanket impl.
//!
//! ```
//! use noble_codec::NobleCbor;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct MyType { a: u32, b: String }
//!
//! let val = MyType { a: 1, b: "test".into() };
//! let bytes = val.canonical_bytes().unwrap();
//! let decoded = MyType::from_cbor(&bytes).unwrap();
//! assert_eq!(val, decoded);
//! ```

mod error;

pub use error::CodecError;

use serde::{de::DeserializeOwned, Serialize};

/// Trait for CBOR serialization with canonical encoding support.
///
/// A blanket implementation is provided for all types implementing
/// `Serialize + DeserializeOwned`, so most types only need to derive
/// those serde traits.
pub trait NobleCbor: Sized {
    /// Serialize this value to CBOR bytes.
    ///
    /// Uses serde's default field ordering (declaration order for structs).
    fn to_cbor(&self) -> Result<Vec<u8>, CodecError>;

    /// Deserialize a value from CBOR bytes.
    fn from_cbor(bytes: &[u8]) -> Result<Self, CodecError>;

    /// Serialize this value to canonical CBOR bytes.
    ///
    /// Canonical encoding sorts all map keys by their encoded byte
    /// representation per RFC 8949 Section 4.2.1. This produces
    /// deterministic output suitable for cryptographic hashing.
    fn canonical_bytes(&self) -> Result<Vec<u8>, CodecError>;
}

impl<T: Serialize + DeserializeOwned> NobleCbor for T {
    fn to_cbor(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| CodecError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        ciborium::from_reader(bytes).map_err(|e| CodecError::Deserialization(e.to_string()))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }
}

/// Serialize a value to canonical CBOR bytes.
///
/// This standalone function requires only `Serialize`, making it usable
/// with borrowed types that don't implement `DeserializeOwned`.
///
/// See [`NobleCbor::canonical_bytes`] for details on canonical encoding.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    // Step 1: Serialize to CBOR bytes
    let mut raw = Vec::new();
    ciborium::into_writer(value, &mut raw)
        .map_err(|e| CodecError::Canonicalization(e.to_string()))?;

    // Step 2: Parse as generic Value to manipulate map key ordering
    let val: ciborium::Value = ciborium::from_reader(raw.as_slice())
        .map_err(|e| CodecError::Canonicalization(e.to_string()))?;

    // Step 3: Recursively sort map keys per RFC 8949
    let canonical = canonicalize_value(val)?;

    // Step 4: Re-serialize to canonical bytes
    let mut buf = Vec::new();
    ciborium::into_writer(&canonical, &mut buf)
        .map_err(|e| CodecError::Canonicalization(e.to_string()))?;
    Ok(buf)
}

/// Recursively canonicalize a CBOR value.
///
/// For maps: sort keys by encoded byte representation (length-first,
/// then lexicographic per RFC 8949 Section 4.2.1).
/// For arrays and tags: recurse into children.
/// For all other values: return unchanged.
fn canonicalize_value(value: ciborium::Value) -> Result<ciborium::Value, CodecError> {
    match value {
        ciborium::Value::Map(entries) => {
            // Pre-compute encoded keys for deterministic sorting
            let mut keyed: Vec<(Vec<u8>, ciborium::Value, ciborium::Value)> =
                Vec::with_capacity(entries.len());

            for (k, v) in entries {
                let ck = canonicalize_value(k)?;
                let cv = canonicalize_value(v)?;
                let mut key_bytes = Vec::new();
                ciborium::into_writer(&ck, &mut key_bytes)
                    .map_err(|e| CodecError::Canonicalization(e.to_string()))?;
                keyed.push((key_bytes, ck, cv));
            }

            // RFC 8949 Section 4.2.1: sort by length first, then lexicographic
            keyed.sort_by(|(a, _, _), (b, _, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

            let sorted = keyed.into_iter().map(|(_, k, v)| (k, v)).collect();
            Ok(ciborium::Value::Map(sorted))
        }
        ciborium::Value::Array(items) => {
            let canonical: Result<Vec<_>, _> = items.into_iter().map(canonicalize_value).collect();
            Ok(ciborium::Value::Array(canonical?))
        }
        ciborium::Value::Tag(tag, inner) => {
            let canonical_inner = canonicalize_value(*inner)?;
            Ok(ciborium::Value::Tag(tag, Box::new(canonical_inner)))
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    // --- Test structs ---

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct Ordered {
        a: u32,
        b: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct Unordered {
        z_field: u32,
        a_field: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct Nested {
        outer_z: Unordered,
        outer_a: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct WithVec {
        items: Vec<u32>,
        name: String,
    }

    // --- Roundtrip tests ---

    #[test]
    fn roundtrip_u32() {
        let val = 42u32;
        let bytes = val.to_cbor().unwrap();
        let decoded = u32::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_string() {
        let val = "hello noble".to_string();
        let bytes = val.to_cbor().unwrap();
        let decoded = String::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_vec() {
        let val = vec![1u32, 2, 3, 100, 0];
        let bytes = val.to_cbor().unwrap();
        let decoded = Vec::<u32>::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_struct() {
        let val = Ordered { a: 10, b: 20 };
        let bytes = val.to_cbor().unwrap();
        let decoded = Ordered::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_nested() {
        let val = Nested {
            outer_z: Unordered {
                z_field: 99,
                a_field: 1,
            },
            outer_a: 42,
        };
        let bytes = val.to_cbor().unwrap();
        let decoded = Nested::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_btreemap() {
        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), 1u32);
        map.insert("apple".to_string(), 2);
        map.insert("mango".to_string(), 3);
        let bytes = map.to_cbor().unwrap();
        let decoded = BTreeMap::<String, u32>::from_cbor(&bytes).unwrap();
        assert_eq!(map, decoded);
    }

    #[test]
    fn roundtrip_with_vec_field() {
        let val = WithVec {
            items: vec![10, 20, 30],
            name: "test".to_string(),
        };
        let bytes = val.to_cbor().unwrap();
        let decoded = WithVec::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    // --- Canonical roundtrip tests ---

    #[test]
    fn canonical_roundtrip_struct() {
        let val = Unordered {
            z_field: 5,
            a_field: 10,
        };
        let canonical = val.canonical_bytes().unwrap();
        let decoded = Unordered::from_cbor(&canonical).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn canonical_roundtrip_nested() {
        let val = Nested {
            outer_z: Unordered {
                z_field: 99,
                a_field: 1,
            },
            outer_a: 42,
        };
        let canonical = val.canonical_bytes().unwrap();
        let decoded = Nested::from_cbor(&canonical).unwrap();
        assert_eq!(val, decoded);
    }

    // --- Canonical key ordering ---

    #[test]
    fn canonical_reorders_map_keys() {
        let val = Unordered {
            z_field: 5,
            a_field: 10,
        };
        let regular = val.to_cbor().unwrap();
        let canonical = val.canonical_bytes().unwrap();

        // Both must decode to the same value
        let from_regular = Unordered::from_cbor(&regular).unwrap();
        let from_canonical = Unordered::from_cbor(&canonical).unwrap();
        assert_eq!(from_regular, from_canonical);

        // In canonical encoding, "a_field" key bytes must appear before "z_field"
        let canonical_hex = hex::encode(&canonical);
        let a_pos = canonical_hex.find("615f6669656c64").unwrap(); // "a_field" without text header
        let z_pos = canonical_hex.find("7a5f6669656c64").unwrap(); // "z_field" without text header
        assert!(
            a_pos < z_pos,
            "canonical encoding must sort 'a_field' before 'z_field'"
        );
    }

    #[test]
    fn canonical_sorts_nested_maps() {
        let val = Nested {
            outer_z: Unordered {
                z_field: 99,
                a_field: 1,
            },
            outer_a: 42,
        };
        let canonical = val.canonical_bytes().unwrap();
        let decoded = Nested::from_cbor(&canonical).unwrap();
        assert_eq!(val, decoded);

        // Verify outer keys are sorted: "outer_a" before "outer_z"
        let hex = hex::encode(&canonical);
        let outer_a_pos = hex.find("6f757465725f61").unwrap(); // "outer_a"
        let outer_z_pos = hex.find("6f757465725f7a").unwrap(); // "outer_z"
        assert!(outer_a_pos < outer_z_pos);
    }

    #[test]
    fn canonical_already_ordered_is_stable() {
        // Ordered { a, b } — keys already in canonical order
        let val = Ordered { a: 1, b: 2 };
        let regular = val.to_cbor().unwrap();
        let canonical = val.canonical_bytes().unwrap();

        // Both should decode identically
        let from_regular = Ordered::from_cbor(&regular).unwrap();
        let from_canonical = Ordered::from_cbor(&canonical).unwrap();
        assert_eq!(from_regular, from_canonical);
    }

    #[test]
    fn canonical_btreemap_sorted() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), 1u32);
        map.insert("a".to_string(), 2);
        map.insert("m".to_string(), 3);

        let canonical = map.canonical_bytes().unwrap();
        let hex = hex::encode(&canonical);

        // Keys in canonical order: "a" < "m" < "z" (same length, lexicographic)
        let a_pos = hex.find("6161").unwrap(); // text(1) "a"
        let m_pos = hex.find("616d").unwrap(); // text(1) "m"
        let z_pos = hex.find("617a").unwrap(); // text(1) "z"
        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    // --- Canonical properties ---

    #[test]
    fn canonical_is_idempotent() {
        let val = Nested {
            outer_z: Unordered {
                z_field: 99,
                a_field: 1,
            },
            outer_a: 42,
        };
        let canonical1 = val.canonical_bytes().unwrap();
        let decoded = Nested::from_cbor(&canonical1).unwrap();
        let canonical2 = decoded.canonical_bytes().unwrap();
        assert_eq!(
            canonical1, canonical2,
            "canonical encoding must be idempotent"
        );
    }

    #[test]
    fn canonical_deterministic_100_iterations() {
        let val = Nested {
            outer_z: Unordered {
                z_field: 42,
                a_field: 7,
            },
            outer_a: 100,
        };
        let reference = val.canonical_bytes().unwrap();
        for i in 0..100 {
            let result = val.canonical_bytes().unwrap();
            assert_eq!(reference, result, "iteration {i} produced different bytes");
        }
    }

    // --- Standalone function ---

    #[test]
    fn standalone_to_canonical_cbor() {
        let val = Unordered {
            z_field: 5,
            a_field: 10,
        };
        let via_trait = val.canonical_bytes().unwrap();
        let via_fn = to_canonical_cbor(&val).unwrap();
        assert_eq!(via_trait, via_fn);
    }

    // --- Error handling ---

    #[test]
    fn error_invalid_cbor() {
        let garbage = &[0xFF, 0xFE, 0xFD];
        let result = Ordered::from_cbor(garbage);
        assert!(result.is_err());
    }

    #[test]
    fn error_empty_input() {
        let result = u32::from_cbor(&[]);
        assert!(result.is_err());
    }

    // --- Hardcoded test vectors (GAP-C5) ---

    #[test]
    fn test_vector_unsigned_integer_42() {
        // CBOR unsigned integer 42: major type 0, additional info 24, value 0x2a
        let bytes = 42u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "182a");
    }

    #[test]
    fn test_vector_unsigned_integer_1() {
        // CBOR unsigned integer 1: major type 0, additional info 1
        let bytes = 1u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "01");
    }

    #[test]
    fn test_vector_unsigned_integer_0() {
        // CBOR unsigned integer 0: major type 0, additional info 0
        let bytes = 0u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "00");
    }

    #[test]
    fn test_vector_text_string() {
        // CBOR text(5) "noble": 0x65 then ASCII bytes
        let bytes = "noble".to_string().to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "656e6f626c65");
    }

    #[test]
    fn test_vector_empty_array() {
        // CBOR empty array: major type 4, additional info 0
        let bytes = Vec::<u32>::new().to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "80");
    }

    #[test]
    fn test_vector_byte_array() {
        // CBOR array [1, 2, 3]: 0x83 0x01 0x02 0x03
        let bytes = vec![1u32, 2, 3].to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "83010203");
    }

    #[test]
    fn test_vector_bool_true() {
        // CBOR true: 0xf5 (major type 7, additional info 21)
        let bytes = true.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "f5");
    }

    #[test]
    fn test_vector_bool_false() {
        // CBOR false: 0xf4 (major type 7, additional info 20)
        let bytes = false.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "f4");
    }
}
