// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! In-house serde CBOR Serializer. Replaces ciborium for all serialization.
//!
//! Produces standard CBOR (RFC 8949) using field declaration order for
//! struct maps. Structs are encoded as CBOR maps with string keys.
//! Enums use external tagging (single-entry map: variant_name → payload).

use crate::cbor;
use crate::CodecError;
use serde::ser::{self, Serialize};

/// Serialize a value to CBOR bytes.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    let mut ser = CborSerializer { buf: &mut buf };
    value.serialize(&mut ser)?;
    Ok(buf)
}

struct CborSerializer<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> ser::Serializer for &'a mut CborSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    type SerializeSeq = SeqSerializer<'a>;
    type SerializeTuple = SeqSerializer<'a>;
    type SerializeTupleStruct = SeqSerializer<'a>;
    type SerializeTupleVariant = SeqSerializer<'a>;
    type SerializeMap = MapSerializer<'a>;
    type SerializeStruct = MapSerializer<'a>;
    type SerializeStructVariant = MapSerializer<'a>;

    fn serialize_bool(self, v: bool) -> Result<(), CodecError> {
        cbor::write_bool(self.buf, v);
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<(), CodecError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i16(self, v: i16) -> Result<(), CodecError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i32(self, v: i32) -> Result<(), CodecError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i64(self, v: i64) -> Result<(), CodecError> {
        if v >= 0 {
            cbor::write_uint(self.buf, v as u64);
        } else {
            // CBOR major type 1: negative integer, encoded as -(1+n)
            let n = (-(v + 1)) as u64;
            write_header(self.buf, 1, n);
        }
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<(), CodecError> {
        cbor::write_uint(self.buf, v as u64);
        Ok(())
    }
    fn serialize_u16(self, v: u16) -> Result<(), CodecError> {
        cbor::write_uint(self.buf, v as u64);
        Ok(())
    }
    fn serialize_u32(self, v: u32) -> Result<(), CodecError> {
        cbor::write_uint(self.buf, v as u64);
        Ok(())
    }
    fn serialize_u64(self, v: u64) -> Result<(), CodecError> {
        cbor::write_uint(self.buf, v);
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<(), CodecError> {
        self.serialize_f64(v as f64)
    }
    fn serialize_f64(self, v: f64) -> Result<(), CodecError> {
        // CBOR major type 7, additional info 27 = 8-byte float
        self.buf.push(0xFB);
        self.buf.extend_from_slice(&v.to_be_bytes());
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<(), CodecError> {
        let mut buf = [0u8; 4];
        self.serialize_str(v.encode_utf8(&mut buf))
    }

    fn serialize_str(self, v: &str) -> Result<(), CodecError> {
        cbor::write_text(self.buf, v);
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<(), CodecError> {
        cbor::write_bytes(self.buf, v);
        Ok(())
    }

    fn serialize_none(self) -> Result<(), CodecError> {
        cbor::write_null(self.buf);
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), CodecError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), CodecError> {
        cbor::write_null(self.buf);
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), CodecError> {
        cbor::write_null(self.buf);
        Ok(())
    }

    fn serialize_unit_variant(
        self, _name: &'static str, _idx: u32, variant: &'static str,
    ) -> Result<(), CodecError> {
        cbor::write_text(self.buf, variant);
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self, _name: &'static str, value: &T,
    ) -> Result<(), CodecError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self, _name: &'static str, _idx: u32, variant: &'static str, value: &T,
    ) -> Result<(), CodecError> {
        cbor::write_map(self.buf, 1);
        cbor::write_text(self.buf, variant);
        value.serialize(&mut CborSerializer { buf: self.buf })
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSerializer<'a>, CodecError> {
        let n = len.ok_or_else(|| CodecError::Serialization("seq length required".into()))?;
        cbor::write_array(self.buf, n);
        Ok(SeqSerializer { buf: self.buf })
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqSerializer<'a>, CodecError> {
        cbor::write_array(self.buf, len);
        Ok(SeqSerializer { buf: self.buf })
    }

    fn serialize_tuple_struct(
        self, _name: &'static str, len: usize,
    ) -> Result<SeqSerializer<'a>, CodecError> {
        cbor::write_array(self.buf, len);
        Ok(SeqSerializer { buf: self.buf })
    }

    fn serialize_tuple_variant(
        self, _name: &'static str, _idx: u32, variant: &'static str, len: usize,
    ) -> Result<SeqSerializer<'a>, CodecError> {
        cbor::write_map(self.buf, 1);
        cbor::write_text(self.buf, variant);
        cbor::write_array(self.buf, len);
        Ok(SeqSerializer { buf: self.buf })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapSerializer<'a>, CodecError> {
        let n = len.ok_or_else(|| CodecError::Serialization("map length required".into()))?;
        cbor::write_map(self.buf, n);
        Ok(MapSerializer { buf: self.buf })
    }

    fn serialize_struct(
        self, _name: &'static str, len: usize,
    ) -> Result<MapSerializer<'a>, CodecError> {
        cbor::write_map(self.buf, len);
        Ok(MapSerializer { buf: self.buf })
    }

    fn serialize_struct_variant(
        self, _name: &'static str, _idx: u32, variant: &'static str, len: usize,
    ) -> Result<MapSerializer<'a>, CodecError> {
        cbor::write_map(self.buf, 1);
        cbor::write_text(self.buf, variant);
        cbor::write_map(self.buf, len);
        Ok(MapSerializer { buf: self.buf })
    }
}

// ── Sequence serializer ─────────────────────────────────────────────────

struct SeqSerializer<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> ser::SerializeSeq for SeqSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

impl<'a> ser::SerializeTuple for SeqSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

impl<'a> ser::SerializeTupleStruct for SeqSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

impl<'a> ser::SerializeTupleVariant for SeqSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

// ── Map/struct serializer ───────────────────────────────────────────────

struct MapSerializer<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> ser::SerializeMap for MapSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), CodecError> {
        key.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CodecError> {
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

impl<'a> ser::SerializeStruct for MapSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self, key: &'static str, value: &T,
    ) -> Result<(), CodecError> {
        cbor::write_text(self.buf, key);
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

impl<'a> ser::SerializeStructVariant for MapSerializer<'a> {
    type Ok = ();
    type Error = CodecError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self, key: &'static str, value: &T,
    ) -> Result<(), CodecError> {
        cbor::write_text(self.buf, key);
        value.serialize(&mut CborSerializer { buf: self.buf })
    }
    fn end(self) -> Result<(), CodecError> { Ok(()) }
}

// ── Helper: CBOR header writer (for negative integers) ──────────────────

fn write_header(buf: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if value < 24 {
        buf.push(prefix | value as u8);
    } else if value <= u8::MAX as u64 {
        buf.push(prefix | 24);
        buf.push(value as u8);
    } else if value <= u16::MAX as u64 {
        buf.push(prefix | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        buf.push(prefix | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(prefix | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

// ── serde Error impl ────────────────────────────────────────────────────

impl ser::Error for CodecError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        CodecError::Serialization(msg.to_string())
    }
}
