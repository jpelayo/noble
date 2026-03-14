// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-house CBOR serialization for the NOBLE protocol.
//!
//! Provides the [`NobleCbor`] trait for serializing and deserializing
//! NOBLE protocol types using CBOR (RFC 8949). No external CBOR dependencies.
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
//! let bytes = val.to_cbor().unwrap();
//! let decoded = MyType::from_cbor(&bytes).unwrap();
//! assert_eq!(val, decoded);
//! ```

mod error;
pub mod cbor;
pub mod cbor_ser;
pub mod cbor_de;

pub use error::CodecError;

use serde::{de::DeserializeOwned, Serialize};

/// Trait for CBOR serialization.
///
/// A blanket implementation is provided for all types implementing
/// `Serialize + DeserializeOwned`, so most types only need to derive
/// those serde traits.
pub trait NobleCbor: Sized {
    /// Serialize this value to CBOR bytes.
    fn to_cbor(&self) -> Result<Vec<u8>, CodecError>;

    /// Deserialize a value from CBOR bytes.
    fn from_cbor(bytes: &[u8]) -> Result<Self, CodecError>;
}

impl<T: Serialize + DeserializeOwned> NobleCbor for T {
    fn to_cbor(&self) -> Result<Vec<u8>, CodecError> {
        cbor_ser::to_cbor(self)
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, CodecError> {
        cbor_de::from_cbor(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

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

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct WithOptional {
        required: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        optional: Option<String>,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    enum TestEnum {
        UnitA,
        UnitB,
        Newtype(u32),
        Struct { x: u32, y: String },
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
            outer_z: Unordered { z_field: 99, a_field: 1 },
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
        let val = WithVec { items: vec![10, 20, 30], name: "test".to_string() };
        let bytes = val.to_cbor().unwrap();
        let decoded = WithVec::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_optional_present() {
        let val = WithOptional { required: 42, optional: Some("yes".into()) };
        let bytes = val.to_cbor().unwrap();
        let decoded = WithOptional::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_optional_absent() {
        let val = WithOptional { required: 42, optional: None };
        let bytes = val.to_cbor().unwrap();
        let decoded = WithOptional::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_enum_unit() {
        let val = TestEnum::UnitA;
        let bytes = val.to_cbor().unwrap();
        let decoded = TestEnum::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_enum_newtype() {
        let val = TestEnum::Newtype(42);
        let bytes = val.to_cbor().unwrap();
        let decoded = TestEnum::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_enum_struct() {
        let val = TestEnum::Struct { x: 1, y: "hi".into() };
        let bytes = val.to_cbor().unwrap();
        let decoded = TestEnum::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn roundtrip_bool() {
        assert_eq!(true, bool::from_cbor(&true.to_cbor().unwrap()).unwrap());
        assert_eq!(false, bool::from_cbor(&false.to_cbor().unwrap()).unwrap());
    }

    #[test]
    fn roundtrip_bytes() {
        let val = vec![0xAA_u8, 0xBB, 0xCC];
        let bytes = val.to_cbor().unwrap();
        let decoded = Vec::<u8>::from_cbor(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    // --- Test vectors ---

    #[test]
    fn test_vector_unsigned_integer_42() {
        let bytes = 42u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "182a");
    }

    #[test]
    fn test_vector_unsigned_integer_1() {
        let bytes = 1u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "01");
    }

    #[test]
    fn test_vector_unsigned_integer_0() {
        let bytes = 0u32.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "00");
    }

    #[test]
    fn test_vector_text_string() {
        let bytes = "noble".to_string().to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "656e6f626c65");
    }

    #[test]
    fn test_vector_empty_array() {
        let bytes = Vec::<u32>::new().to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "80");
    }

    #[test]
    fn test_vector_byte_array() {
        let bytes = vec![1u32, 2, 3].to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "83010203");
    }

    #[test]
    fn test_vector_bool_true() {
        let bytes = true.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "f5");
    }

    #[test]
    fn test_vector_bool_false() {
        let bytes = false.to_cbor().unwrap();
        assert_eq!(hex::encode(&bytes), "f4");
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
}
