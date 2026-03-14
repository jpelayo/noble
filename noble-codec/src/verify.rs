// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Codec round-trip verification for install-time checks.
//!
//! Verifies that the in-house CBOR serializer and deserializer produce
//! byte-identical round-trips for representative protocol types.

use crate::{cbor_de, cbor_ser, CodecError};
use serde::{Deserialize, Serialize};

/// Result of a single codec round-trip check.
pub struct CodecCheckResult {
    pub name: &'static str,
    pub pass: bool,
    pub bytes: usize,
    pub detail: String,
}

/// Run all codec round-trip checks. Returns results for each type.
pub fn verify_all_codecs() -> Vec<CodecCheckResult> {
    let mut results = Vec::new();

    // Primitives
    results.push(check_roundtrip("u8(255)", &255u8));
    results.push(check_roundtrip("u16(65535)", &65535u16));
    results.push(check_roundtrip("u32(4294967295)", &4294967295u32));
    results.push(check_roundtrip("u64(max)", &u64::MAX));
    results.push(check_roundtrip("i64(-1)", &(-1i64)));
    results.push(check_roundtrip("bool(true)", &true));
    results.push(check_roundtrip("String", &"noble protocol".to_string()));
    results.push(check_roundtrip("Vec<u8>", &vec![0xAAu8, 0xBB, 0xCC]));
    results.push(check_roundtrip("Vec<u32>", &vec![1u32, 2, 3, 100]));
    results.push(check_roundtrip("Option::None", &None::<u32>));
    results.push(check_roundtrip("Option::Some(42)", &Some(42u32)));
    results.push(check_roundtrip("f64(3.14)", &3.14f64));

    // Structs
    results.push(check_roundtrip("SimpleStruct", &TestStruct { x: 42, name: "test".into() }));
    results.push(check_roundtrip("NestedStruct", &NestedStruct {
        inner: TestStruct { x: 99, name: "nested".into() },
        flag: true,
    }));

    // Enums
    results.push(check_roundtrip("Enum::Unit", &TestEnum::UnitA));
    results.push(check_roundtrip("Enum::Newtype", &TestEnum::Newtype(42)));
    results.push(check_roundtrip("Enum::Struct", &TestEnum::Struct { a: 1, b: "hi".into() }));

    // Fixed-size arrays (critical for [u8; 32] hashes)
    results.push(check_roundtrip("[u8; 32]", &[0x33u8; 32]));

    // Optional fields with skip_serializing_if
    results.push(check_roundtrip("OptionalFields(none)", &OptionalFields {
        required: 42,
        optional: None,
        items: vec![],
    }));
    results.push(check_roundtrip("OptionalFields(some)", &OptionalFields {
        required: 42,
        optional: Some("yes".into()),
        items: vec![1, 2, 3],
    }));

    // BTreeMap (used in some storage types)
    let mut map = std::collections::BTreeMap::new();
    map.insert("zebra".to_string(), 1u32);
    map.insert("apple".to_string(), 2);
    results.push(check_roundtrip("BTreeMap", &map));

    // Idempotency: encode twice, must match
    results.push(check_idempotent("Idempotent(struct)", &TestStruct { x: 7, name: "idem".into() }));
    results.push(check_idempotent("Idempotent(enum)", &TestEnum::Struct { a: 99, b: "check".into() }));

    results
}

// ── Test types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestStruct {
    x: u32,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NestedStruct {
    inner: TestStruct,
    flag: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum TestEnum {
    UnitA,
    Newtype(u32),
    Struct { a: u32, b: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OptionalFields {
    required: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    optional: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    items: Vec<u32>,
}

// ── Check helpers ───────────────────────────────────────────────────────

fn check_roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
    name: &'static str,
    value: &T,
) -> CodecCheckResult {
    match roundtrip_inner(value) {
        Ok(bytes) => CodecCheckResult {
            name,
            pass: true,
            bytes,
            detail: String::new(),
        },
        Err(e) => CodecCheckResult {
            name,
            pass: false,
            bytes: 0,
            detail: e.to_string(),
        },
    }
}

fn roundtrip_inner<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
    value: &T,
) -> Result<usize, CodecError> {
    let bytes = cbor_ser::to_cbor(value)?;
    let decoded: T = cbor_de::from_cbor(&bytes)?;
    if &decoded != value {
        return Err(CodecError::Deserialization(format!(
            "roundtrip mismatch: {value:?} != {decoded:?}"
        )));
    }
    Ok(bytes.len())
}

fn check_idempotent<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
    name: &'static str,
    value: &T,
) -> CodecCheckResult {
    let r1 = cbor_ser::to_cbor(value);
    let r2 = cbor_ser::to_cbor(value);
    match (r1, r2) {
        (Ok(b1), Ok(b2)) => {
            if b1 == b2 {
                CodecCheckResult { name, pass: true, bytes: b1.len(), detail: String::new() }
            } else {
                CodecCheckResult {
                    name,
                    pass: false,
                    bytes: b1.len(),
                    detail: format!("NOT idempotent: {} vs {} bytes", b1.len(), b2.len()),
                }
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            CodecCheckResult { name, pass: false, bytes: 0, detail: e.to_string() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_codec_checks_pass() {
        let results = verify_all_codecs();
        for r in &results {
            assert!(r.pass, "CODEC CHECK FAILED: {} — {}", r.name, r.detail);
        }
    }
}
