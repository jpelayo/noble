// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// CBOR encoder derived from ciborium-ll 0.2.2 (Apache-2.0).
// See LICENSE-THIRD-PARTY for full attribution.
//
// This is a minimal, frozen CBOR encoder for the NOBLE protocol's
// cryptographic hashing path. It produces RFC 7049 / RFC 8949
// compliant CBOR bytes without any external dependencies.
//
// FROZEN: Do not modify encoding behavior. Any change invalidates
// all existing block hashes, transaction IDs, and signatures.

/// CBOR major types (3-bit prefix in the first byte).
const MAJOR_UINT: u8 = 0;     // Major type 0: unsigned integer
const MAJOR_BYTES: u8 = 2;    // Major type 2: byte string
const MAJOR_TEXT: u8 = 3;     // Major type 3: UTF-8 text string
const MAJOR_ARRAY: u8 = 4;    // Major type 4: array
const MAJOR_MAP: u8 = 5;      // Major type 5: map
const MAJOR_SIMPLE: u8 = 7;   // Major type 7: simple values and floats

/// Write the CBOR header (major type + argument) using minimal encoding.
///
/// RFC 8949 Section 3.1: The argument is encoded in the shortest form
/// that can represent the value.
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

/// Write a CBOR unsigned integer (major type 0).
pub fn write_uint(buf: &mut Vec<u8>, value: u64) {
    write_header(buf, MAJOR_UINT, value);
}

/// Write a CBOR byte string (major type 2).
///
/// Used for: Hash256, Vec<u8>, [u8; N], NoblePublicKey wire bytes,
/// NobleAddress wire bytes, SignatureEnvelope wire bytes.
pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_header(buf, MAJOR_BYTES, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Write a CBOR UTF-8 text string (major type 3).
///
/// Used for: struct field names (map keys), String fields,
/// MetadataEntry.key, ExternalAttestation.scheme/scope.
pub fn write_text(buf: &mut Vec<u8>, s: &str) {
    write_header(buf, MAJOR_TEXT, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

/// Write a CBOR array header (major type 4) with definite length.
///
/// Caller must write exactly `len` items after this call.
pub fn write_array(buf: &mut Vec<u8>, len: usize) {
    write_header(buf, MAJOR_ARRAY, len as u64);
}

/// Write a CBOR map header (major type 5) with definite length.
///
/// Caller must write exactly `len` key-value pairs after this call.
/// Keys must be sorted by encoded byte representation for canonical CBOR.
pub fn write_map(buf: &mut Vec<u8>, len: usize) {
    write_header(buf, MAJOR_MAP, len as u64);
}

/// Write a CBOR boolean (major type 7, simple values 20/21).
pub fn write_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push((MAJOR_SIMPLE << 5) | if value { 21 } else { 20 });
}

/// Write a CBOR null (major type 7, simple value 22).
#[allow(dead_code)]
pub fn write_null(buf: &mut Vec<u8>) {
    buf.push((MAJOR_SIMPLE << 5) | 22);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_minimal_encoding() {
        // 0-23: single byte
        let mut buf = Vec::new();
        write_uint(&mut buf, 0);
        assert_eq!(buf, [0x00]);

        buf.clear();
        write_uint(&mut buf, 23);
        assert_eq!(buf, [0x17]);

        // 24-255: prefix 0x18 + 1 byte
        buf.clear();
        write_uint(&mut buf, 24);
        assert_eq!(buf, [0x18, 0x18]);

        buf.clear();
        write_uint(&mut buf, 255);
        assert_eq!(buf, [0x18, 0xFF]);

        // 256-65535: prefix 0x19 + 2 bytes BE
        buf.clear();
        write_uint(&mut buf, 256);
        assert_eq!(buf, [0x19, 0x01, 0x00]);

        buf.clear();
        write_uint(&mut buf, 1000);
        assert_eq!(buf, [0x19, 0x03, 0xE8]);

        // 65536-2^32-1: prefix 0x1A + 4 bytes BE
        buf.clear();
        write_uint(&mut buf, 100_000);
        assert_eq!(buf, [0x1A, 0x00, 0x01, 0x86, 0xA0]);

        // > 2^32: prefix 0x1B + 8 bytes BE
        buf.clear();
        write_uint(&mut buf, 1_000_000_000_000);
        assert_eq!(buf, [0x1B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00]);
    }

    #[test]
    fn bytes_encoding() {
        let mut buf = Vec::new();
        write_bytes(&mut buf, &[]);
        assert_eq!(buf, [0x40]); // empty byte string

        buf.clear();
        write_bytes(&mut buf, &[0xAA, 0xBB]);
        assert_eq!(buf, [0x42, 0xAA, 0xBB]); // 2-byte string

        // 32-byte hash (common in Noble)
        buf.clear();
        write_bytes(&mut buf, &[0x00; 32]);
        assert_eq!(buf[0], 0x58); // major 2, minor 24 (1-byte length)
        assert_eq!(buf[1], 0x20); // length = 32
        assert_eq!(buf.len(), 34);
    }

    #[test]
    fn text_encoding() {
        let mut buf = Vec::new();
        write_text(&mut buf, "");
        assert_eq!(buf, [0x60]); // empty text

        buf.clear();
        write_text(&mut buf, "a");
        assert_eq!(buf, [0x61, b'a']); // 1-char text

        buf.clear();
        write_text(&mut buf, "version");
        assert_eq!(buf[0], 0x67); // major 3, length 7
        assert_eq!(&buf[1..], b"version");
    }

    #[test]
    fn array_and_map_headers() {
        let mut buf = Vec::new();
        write_array(&mut buf, 0);
        assert_eq!(buf, [0x80]); // empty array

        buf.clear();
        write_array(&mut buf, 3);
        assert_eq!(buf, [0x83]); // 3-element array

        buf.clear();
        write_map(&mut buf, 0);
        assert_eq!(buf, [0xA0]); // empty map

        buf.clear();
        write_map(&mut buf, 2);
        assert_eq!(buf, [0xA2]); // 2-pair map
    }

    #[test]
    fn bool_and_null() {
        let mut buf = Vec::new();
        write_bool(&mut buf, false);
        assert_eq!(buf, [0xF4]);

        buf.clear();
        write_bool(&mut buf, true);
        assert_eq!(buf, [0xF5]);

        buf.clear();
        write_null(&mut buf);
        assert_eq!(buf, [0xF6]);
    }
}
