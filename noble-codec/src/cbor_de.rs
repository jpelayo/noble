// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! In-house serde CBOR Deserializer. Replaces ciborium for all deserialization.
//!
//! Parses standard CBOR (RFC 8949) byte streams into Rust types via serde.
//! Structs are expected as CBOR maps with string keys (field names).
//! Enums use external tagging (single-entry map: variant_name → payload).

use crate::CodecError;
use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};

/// Deserialize a value from CBOR bytes.
pub fn from_cbor<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let mut de = CborDeserializer::new(bytes);
    let value = T::deserialize(&mut de)?;
    if de.pos != de.input.len() {
        return Err(CodecError::Deserialization(format!(
            "trailing bytes: {} unconsumed after position {}",
            de.input.len() - de.pos,
            de.pos,
        )));
    }
    Ok(value)
}

/// Maximum CBOR nesting depth. This deserializer parses untrusted input (gossip
/// messages, sync bodies); without a bound, a deeply-nested blob — or an unknown
/// field skipped via `IgnoredAny` → `deserialize_any` → seq/map — recurses until
/// the stack overflows and the process aborts. 128 is far deeper than any
/// legitimate Noble wire type. Enforced in `deserialize_seq`/`deserialize_map`,
/// the only two recursion points (all nesting funnels through them).
const MAX_CBOR_DEPTH: u32 = 128;

struct CborDeserializer<'de> {
    input: &'de [u8],
    pos: usize,
    depth: u32,
}

impl<'de> CborDeserializer<'de> {
    fn new(input: &'de [u8]) -> Self {
        Self { input, pos: 0, depth: 0 }
    }

    fn peek(&self) -> Result<u8, CodecError> {
        self.input.get(self.pos).copied()
            .ok_or_else(|| CodecError::Deserialization("unexpected end of input".into()))
    }

    fn next(&mut self) -> Result<u8, CodecError> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'de [u8], CodecError> {
        if self.pos + n > self.input.len() {
            return Err(CodecError::Deserialization(format!(
                "need {} bytes at pos {}, have {}",
                n, self.pos, self.input.len() - self.pos
            )));
        }
        let slice = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read the CBOR argument (additional info value) from the initial byte.
    fn read_argument(&mut self, additional: u8) -> Result<u64, CodecError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => Ok(self.next()? as u64),
            25 => {
                let bytes = self.read_bytes(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => Err(CodecError::Deserialization(format!("invalid additional info: {additional}"))),
        }
    }

    /// Read a CBOR header: returns (major_type, argument).
    fn read_header(&mut self) -> Result<(u8, u64), CodecError> {
        let initial = self.next()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;
        let arg = self.read_argument(additional)?;
        Ok((major, arg))
    }

    /// Peek at major type without consuming.
    fn peek_major(&self) -> Result<u8, CodecError> {
        Ok(self.peek()? >> 5)
    }
}

impl<'a, 'de> de::Deserializer<'de> for &'a mut CborDeserializer<'de> {
    type Error = CodecError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let major = self.peek_major()?;
        match major {
            0 => self.deserialize_u64(visitor),
            1 => self.deserialize_i64(visitor),
            2 => self.deserialize_bytes(visitor),
            3 => self.deserialize_str(visitor),
            4 => self.deserialize_seq(visitor),
            5 => self.deserialize_map(visitor),
            7 => {
                let b = self.peek()?;
                match b {
                    0xF4 | 0xF5 => self.deserialize_bool(visitor),
                    0xF6 | 0xF7 => self.deserialize_option(visitor),
                    0xF9 | 0xFA | 0xFB => self.deserialize_f64(visitor),
                    _ => Err(CodecError::Deserialization(format!("unsupported simple value: {b:#x}"))),
                }
            }
            _ => Err(CodecError::Deserialization(format!("unsupported major type: {major}"))),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let b = self.next()?;
        match b {
            0xF4 => visitor.visit_bool(false),
            0xF5 => visitor.visit_bool(true),
            _ => Err(CodecError::Deserialization(format!("expected bool, got {b:#x}"))),
        }
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, arg) = self.read_header()?;
        if major != 0 { return Err(CodecError::Deserialization(format!("expected uint, got major {major}"))); }
        if arg > u8::MAX as u64 { return Err(CodecError::Deserialization(format!("u8 overflow: {arg}"))); }
        visitor.visit_u8(arg as u8)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, arg) = self.read_header()?;
        if major != 0 { return Err(CodecError::Deserialization(format!("expected uint, got major {major}"))); }
        if arg > u16::MAX as u64 { return Err(CodecError::Deserialization(format!("u16 overflow: {arg}"))); }
        visitor.visit_u16(arg as u16)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, arg) = self.read_header()?;
        if major != 0 { return Err(CodecError::Deserialization(format!("expected uint, got major {major}"))); }
        if arg > u32::MAX as u64 { return Err(CodecError::Deserialization(format!("u32 overflow: {arg}"))); }
        visitor.visit_u32(arg as u32)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, arg) = self.read_header()?;
        if major != 0 { return Err(CodecError::Deserialization(format!("expected uint, got major {major}"))); }
        visitor.visit_u64(arg)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, arg) = self.read_header()?;
        match major {
            0 => {
                if arg > i64::MAX as u64 {
                    return Err(CodecError::Deserialization(format!("i64 overflow: unsigned {arg}")));
                }
                visitor.visit_i64(arg as i64)
            }
            1 => {
                // CBOR negative: value = -(1 + arg). Check overflow.
                if arg > i64::MAX as u64 {
                    return Err(CodecError::Deserialization(format!("i64 overflow: negative arg {arg}")));
                }
                visitor.visit_i64(-(arg as i64) - 1)
            }
            _ => Err(CodecError::Deserialization(format!("expected int, got major {major}"))),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_f64(visitor)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let b = self.next()?;
        match b {
            0xF9 => {
                // Half-precision (16-bit) float — skip 2 bytes, decode manually
                let bytes = self.read_bytes(2)?;
                let bits = u16::from_be_bytes([bytes[0], bytes[1]]);
                let sign = ((bits >> 15) & 1) as u64;
                let exp = ((bits >> 10) & 0x1F) as i32;
                let mant = (bits & 0x3FF) as u64;
                let val = if exp == 0 {
                    // Subnormal
                    let f = (mant as f64) * 2.0_f64.powi(-24);
                    if sign == 1 { -f } else { f }
                } else if exp == 31 {
                    if mant == 0 { if sign == 1 { f64::NEG_INFINITY } else { f64::INFINITY } }
                    else { f64::NAN }
                } else {
                    let f = ((mant as f64) / 1024.0 + 1.0) * 2.0_f64.powi(exp - 15);
                    if sign == 1 { -f } else { f }
                };
                visitor.visit_f64(val)
            }
            0xFA => {
                // Single-precision (32-bit) float
                let bytes = self.read_bytes(4)?;
                let val = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                visitor.visit_f64(val as f64)
            }
            0xFB => {
                // Double-precision (64-bit) float
                let bytes = self.read_bytes(8)?;
                let val = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                visitor.visit_f64(val)
            }
            _ => Err(CodecError::Deserialization(format!("expected float, got {b:#x}"))),
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, len) = self.read_header()?;
        if major != 3 { return Err(CodecError::Deserialization(format!("expected text, got major {major}"))); }
        let bytes = self.read_bytes(len as usize)?;
        let s = std::str::from_utf8(bytes)
            .map_err(|e| CodecError::Deserialization(format!("invalid utf8: {e}")))?;
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, len) = self.read_header()?;
        if major != 2 { return Err(CodecError::Deserialization(format!("expected bytes, got major {major}"))); }
        let bytes = self.read_bytes(len as usize)?;
        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let b = self.peek()?;
        if b == 0xF6 || b == 0xF7 {
            self.pos += 1; // consume null
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let b = self.next()?;
        if b == 0xF6 || b == 0xF7 {
            visitor.visit_unit()
        } else {
            Err(CodecError::Deserialization(format!("expected null, got {b:#x}")))
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self, _name: &'static str, visitor: V,
    ) -> Result<V::Value, CodecError> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self, _name: &'static str, visitor: V,
    ) -> Result<V::Value, CodecError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, len) = self.read_header()?;
        if major == 4 {
            // CBOR array — standard sequence of elements. Bound recursion depth
            // (reborrow `&mut *self` so we can decrement after visit_seq returns).
            self.depth += 1;
            if self.depth > MAX_CBOR_DEPTH {
                return Err(CodecError::Deserialization("max CBOR nesting depth exceeded".into()));
            }
            let r = visitor.visit_seq(SeqAccess { de: &mut *self, remaining: len as usize });
            self.depth -= 1;
            r
        } else if major == 2 {
            // CBOR byte string — accept as a sequence of u8.
            // This allows Vec<u8> and [u8; N] to deserialize from byte strings
            // (the natural CBOR representation for binary data), not just from
            // arrays of integers. Clients encode binary data as byte strings;
            // serde expects sequences. This bridge makes both representations work.
            let bytes = self.read_bytes(len as usize)?;
            visitor.visit_seq(ByteSeqAccess { bytes, pos: 0 })
        } else {
            Err(CodecError::Deserialization(format!("expected array or byte string, got major {major}")))
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self, _name: &'static str, _len: usize, visitor: V,
    ) -> Result<V::Value, CodecError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        let (major, len) = self.read_header()?;
        if major != 5 { return Err(CodecError::Deserialization(format!("expected map, got major {major}"))); }
        // Bound recursion depth — maps nest via struct/enum fields and via
        // IgnoredAny when skipping unknown keys. Reborrow so we decrement after.
        self.depth += 1;
        if self.depth > MAX_CBOR_DEPTH {
            return Err(CodecError::Deserialization("max CBOR nesting depth exceeded".into()));
        }
        let r = visitor.visit_map(MapAccess { de: &mut *self, remaining: len as usize });
        self.depth -= 1;
        r
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self, _name: &'static str, _fields: &'static [&'static str], visitor: V,
    ) -> Result<V::Value, CodecError> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self, _name: &'static str, _variants: &'static [&'static str], visitor: V,
    ) -> Result<V::Value, CodecError> {
        let major = self.peek_major()?;
        match major {
            3 => {
                // Unit variant: just a text string
                visitor.visit_enum(UnitVariantAccess { de: self })
            }
            5 => {
                // Newtype/struct/tuple variant: map with 1 entry
                let (_, len) = self.read_header()?;
                if len != 1 {
                    return Err(CodecError::Deserialization(format!("enum map must have 1 entry, got {len}")));
                }
                visitor.visit_enum(VariantAccess { de: self })
            }
            _ => Err(CodecError::Deserialization(format!("expected text or map for enum, got major {major}"))),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, CodecError> {
        self.deserialize_any(visitor)
    }
}

// ── SeqAccess ───────────────────────────────────────────────────────────

struct SeqAccess<'a, 'de> {
    de: &'a mut CborDeserializer<'de>,
    remaining: usize,
}

impl<'a, 'de> de::SeqAccess<'de> for SeqAccess<'a, 'de> {
    type Error = CodecError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, CodecError> {
        if self.remaining == 0 { return Ok(None); }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

/// Sequence access that yields individual bytes from a CBOR byte string.
/// Allows `Vec<u8>` and `[u8; N]` to deserialize from CBOR byte strings (major 2).
struct ByteSeqAccess<'de> {
    bytes: &'de [u8],
    pos: usize,
}

impl<'de> de::SeqAccess<'de> for ByteSeqAccess<'de> {
    type Error = CodecError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, CodecError> {
        if self.pos >= self.bytes.len() { return Ok(None); }
        let byte = self.bytes[self.pos];
        self.pos += 1;
        seed.deserialize(byte.into_deserializer()).map(Some)
    }
}

// ── MapAccess ───────────────────────────────────────────────────────────

struct MapAccess<'a, 'de> {
    de: &'a mut CborDeserializer<'de>,
    remaining: usize,
}

impl<'a, 'de> de::MapAccess<'de> for MapAccess<'a, 'de> {
    type Error = CodecError;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, CodecError> {
        if self.remaining == 0 { return Ok(None); }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, CodecError> {
        seed.deserialize(&mut *self.de)
    }
}

// ── Enum access (unit variant) ──────────────────────────────────────────

struct UnitVariantAccess<'a, 'de> {
    de: &'a mut CborDeserializer<'de>,
}

impl<'a, 'de> de::EnumAccess<'de> for UnitVariantAccess<'a, 'de> {
    type Error = CodecError;
    type Variant = UnitOnly;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, UnitOnly), CodecError> {
        let val = seed.deserialize(&mut *self.de)?;
        Ok((val, UnitOnly))
    }
}

struct UnitOnly;
impl<'de> de::VariantAccess<'de> for UnitOnly {
    type Error = CodecError;
    fn unit_variant(self) -> Result<(), CodecError> { Ok(()) }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _seed: T) -> Result<T::Value, CodecError> {
        Err(CodecError::Deserialization("expected unit variant".into()))
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value, CodecError> {
        Err(CodecError::Deserialization("expected unit variant".into()))
    }
    fn struct_variant<V: Visitor<'de>>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value, CodecError> {
        Err(CodecError::Deserialization("expected unit variant".into()))
    }
}

// ── Enum access (newtype/struct/tuple variant) ──────────────────────────

struct VariantAccess<'a, 'de> {
    de: &'a mut CborDeserializer<'de>,
}

impl<'a, 'de> de::EnumAccess<'de> for VariantAccess<'a, 'de> {
    type Error = CodecError;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), CodecError> {
        let val = seed.deserialize(&mut *self.de)?;
        Ok((val, self))
    }
}

impl<'a, 'de> de::VariantAccess<'de> for VariantAccess<'a, 'de> {
    type Error = CodecError;
    fn unit_variant(self) -> Result<(), CodecError> { Ok(()) }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, CodecError> {
        seed.deserialize(&mut *self.de)
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_seq(&mut *self.de, visitor)
    }
    fn struct_variant<V: Visitor<'de>>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value, CodecError> {
        de::Deserializer::deserialize_struct(&mut *self.de, "", fields, visitor)
    }
}

// ── serde Error impl ────────────────────────────────────────────────────

impl de::Error for CodecError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        CodecError::Deserialization(msg.to_string())
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;

    #[test]
    fn deeply_nested_cbor_is_rejected() {
        // N (> MAX_CBOR_DEPTH) nested 1-element CBOR arrays (0x81) then uint 0
        // (0x00). Deserializing as IgnoredAny drives deserialize_any -> seq
        // recursion — exactly the unknown-field-skip attack path. With the depth
        // guard this returns an error instead of recursing toward a stack abort.
        let n = MAX_CBOR_DEPTH as usize + 50;
        let mut blob = vec![0x81u8; n];
        blob.push(0x00);
        let r = from_cbor::<serde::de::IgnoredAny>(&blob);
        assert!(r.is_err(), "deeply nested CBOR must be rejected, not overflow");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("depth"), "expected a depth error, got: {msg}");
    }

    #[test]
    fn normal_nesting_still_decodes() {
        // Legitimate, modestly-nested data (well under MAX) round-trips — the
        // guard does not reject normal structures.
        let v: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5]];
        let bytes = crate::cbor_ser::to_cbor(&v).unwrap();
        let decoded: Vec<Vec<u8>> = from_cbor(&bytes).unwrap();
        assert_eq!(decoded, v);
    }
}
