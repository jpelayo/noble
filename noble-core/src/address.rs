// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Dual-address system supporting both native NOBLE public keys and Bitcoin-format addresses.
//!
//! `NobleAddress` is the canonical address type used for balance tracking, transaction
//! recipients, and reward addresses. It supports:
//!
//! - **Native NOBLE keys** (secp256k1) — for validators and direct protocol users
//! - **Bitcoin Hash160** (P2PKH/P2WPKH) — 20-byte `RIPEMD160(SHA256(pubkey))`
//! - **Bitcoin Taproot** (P2TR) — 32-byte x-only public key
//!
//! # Wire format (DB key prefix)
//!
//! | Type | Prefix | Data | Total |
//! |------|--------|------|-------|
//! | secp256k1 | `0x02` | 33 bytes | 34 |
//! | Bitcoin Hash160 | `0x80` | 20 bytes | 21 |
//! | Bitcoin Taproot | `0x81` | 32 bytes | 33 |

use noble_crypto::keys::NoblePublicKey;
use noble_crypto::schemes::SCHEME_SECP256K1;
use serde::{Deserialize, Serialize};

/// Wire prefix for Bitcoin Hash160 addresses (P2PKH / P2WPKH).
pub const PREFIX_BITCOIN_HASH160: u8 = 0x80;

/// Wire prefix for Bitcoin Taproot addresses (P2TR).
pub const PREFIX_BITCOIN_TAPROOT: u8 = 0x81;

/// A unified address type for the NOBLE protocol balance system.
///
/// Supports both native NOBLE public keys and Bitcoin-format addresses as
/// first-class citizens in the balance database.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NobleAddress {
    /// Native NOBLE public key (secp256k1).
    Noble(NoblePublicKey),
    /// Bitcoin P2PKH/P2WPKH — 20-byte Hash160(pubkey).
    /// P2PKH (`1...`) and P2WPKH (`bc1q...`) for the same pubkey share this variant.
    BitcoinHash160([u8; 20]),
    /// Bitcoin P2TR Taproot — 32-byte x-only pubkey.
    BitcoinTaproot([u8; 32]),
}

impl NobleAddress {
    /// Encode to wire format for database storage.
    ///
    /// Format: `[prefix || data]` where prefix identifies the address type.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        match self {
            NobleAddress::Noble(pk) => pk.to_wire_bytes(),
            NobleAddress::BitcoinHash160(hash) => {
                let mut wire = Vec::with_capacity(1 + 20);
                wire.push(PREFIX_BITCOIN_HASH160);
                wire.extend_from_slice(hash);
                wire
            }
            NobleAddress::BitcoinTaproot(xonly) => {
                let mut wire = Vec::with_capacity(1 + 32);
                wire.push(PREFIX_BITCOIN_TAPROOT);
                wire.extend_from_slice(xonly);
                wire
            }
        }
    }

    /// Decode from wire format.
    ///
    /// Accepts prefix bytes: `0x02` (secp256k1),
    /// `0x80` (Hash160), `0x81` (Taproot).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.is_empty() {
            return Err(AddressError::EmptyInput);
        }

        let prefix = bytes[0];
        let data = &bytes[1..];

        match prefix {
            SCHEME_SECP256K1 => {
                let pk = NoblePublicKey::from_wire_bytes(bytes)
                    .map_err(|e| AddressError::InvalidKey(e.to_string()))?;
                Ok(NobleAddress::Noble(pk))
            }
            PREFIX_BITCOIN_HASH160 => {
                if data.len() != 20 {
                    return Err(AddressError::InvalidLength {
                        expected: 20,
                        got: data.len(),
                        kind: "Bitcoin Hash160",
                    });
                }
                let mut hash = [0u8; 20];
                hash.copy_from_slice(data);
                Ok(NobleAddress::BitcoinHash160(hash))
            }
            PREFIX_BITCOIN_TAPROOT => {
                if data.len() != 32 {
                    return Err(AddressError::InvalidLength {
                        expected: 32,
                        got: data.len(),
                        kind: "Bitcoin Taproot",
                    });
                }
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(data);
                Ok(NobleAddress::BitcoinTaproot(xonly))
            }
            _ => Err(AddressError::UnknownPrefix(prefix)),
        }
    }

    /// Returns the wire prefix byte for this address type.
    pub fn prefix(&self) -> u8 {
        match self {
            NobleAddress::Noble(pk) => pk.scheme_id(),
            NobleAddress::BitcoinHash160(_) => PREFIX_BITCOIN_HASH160,
            NobleAddress::BitcoinTaproot(_) => PREFIX_BITCOIN_TAPROOT,
        }
    }

    /// Returns a human-readable address type string.
    pub fn address_type(&self) -> &'static str {
        match self {
            NobleAddress::Noble(NoblePublicKey::Secp256k1(_)) => "secp256k1",
            NobleAddress::BitcoinHash160(_) => "bitcoin_hash160",
            NobleAddress::BitcoinTaproot(_) => "bitcoin_taproot",
        }
    }

    /// Returns the raw data bytes (without prefix).
    pub fn data_bytes(&self) -> &[u8] {
        match self {
            NobleAddress::Noble(pk) => pk.key_bytes(),
            NobleAddress::BitcoinHash160(h) => h,
            NobleAddress::BitcoinTaproot(x) => x,
        }
    }

    /// Display as hex string (prefix + data).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_wire_bytes())
    }

    /// Human-readable display address.
    ///
    /// - Noble native keys → `nbl1p…` (secp256k1)
    /// - Bitcoin Hash160 → `bc1q…` (P2WPKH)
    /// - Bitcoin Taproot → `bc1p…` (P2TR)
    pub fn to_display_address(&self) -> String {
        match self {
            NobleAddress::Noble(pk) => noble_crypto::noble_addr::encode(pk),
            NobleAddress::BitcoinHash160(hash) => {
                noble_crypto::bitcoin_addr::hash160_to_p2wpkh(hash, true)
            }
            NobleAddress::BitcoinTaproot(xonly) => {
                noble_crypto::bitcoin_addr::xonly_to_p2tr(xonly, true)
            }
        }
    }

    /// For a secp256k1 public key, derive the corresponding BitcoinHash160 address.
    /// Only applies to secp256k1 keys.
    pub fn bitcoin_hash160_for_pubkey(pk: &NoblePublicKey) -> Option<NobleAddress> {
        match pk {
            NoblePublicKey::Secp256k1(bytes) => {
                let h160 = noble_crypto::bitcoin_addr::hash160(bytes);
                Some(NobleAddress::BitcoinHash160(h160))
            }
            _ => None,
        }
    }

    /// For a secp256k1 public key, derive the corresponding BitcoinTaproot address.
    ///
    /// Applies the BIP-341 key-path-only tweak: the stored 32-byte output key is
    /// `x(P + tagged_hash("TapTweak", x(P)) · G)`, NOT the raw x-only pubkey.
    /// Only applies to secp256k1 keys.
    pub fn bitcoin_taproot_for_pubkey(pk: &NoblePublicKey) -> Option<NobleAddress> {
        match pk {
            NoblePublicKey::Secp256k1(bytes) if bytes.len() == 33 => {
                let compressed: [u8; 33] = bytes.as_slice().try_into().ok()?;
                let output_key = noble_crypto::bitcoin_addr::taproot_tweak_pubkey(&compressed)?;
                Some(NobleAddress::BitcoinTaproot(output_key))
            }
            _ => None,
        }
    }
}

impl From<NoblePublicKey> for NobleAddress {
    fn from(pk: NoblePublicKey) -> Self {
        NobleAddress::Noble(pk)
    }
}

/// Errors from NobleAddress parsing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AddressError {
    #[error("empty input")]
    EmptyInput,
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("{kind}: expected {expected} bytes, got {got}")]
    InvalidLength {
        expected: usize,
        got: usize,
        kind: &'static str,
    },
    #[error("unknown address prefix: 0x{0:02x}")]
    UnknownPrefix(u8),
    #[error("invalid Bitcoin address: {0}")]
    InvalidBitcoinAddress(String),
    #[error("unsupported address format: {0}")]
    UnsupportedFormat(String),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("checksum mismatch")]
    ChecksumMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::secp256k1;

    #[test]
    fn noble_secp256k1_roundtrip() {
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let pk = NoblePublicKey::Secp256k1(pk_bytes);
        let addr = NobleAddress::Noble(pk.clone());

        let wire = addr.to_wire_bytes();
        assert_eq!(wire[0], SCHEME_SECP256K1);
        assert_eq!(wire.len(), 34);

        let decoded = NobleAddress::from_wire_bytes(&wire).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn bitcoin_hash160_roundtrip() {
        let hash = [0xab; 20];
        let addr = NobleAddress::BitcoinHash160(hash);

        let wire = addr.to_wire_bytes();
        assert_eq!(wire[0], PREFIX_BITCOIN_HASH160);
        assert_eq!(wire.len(), 21);

        let decoded = NobleAddress::from_wire_bytes(&wire).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn bitcoin_taproot_roundtrip() {
        let xonly = [0xcd; 32];
        let addr = NobleAddress::BitcoinTaproot(xonly);

        let wire = addr.to_wire_bytes();
        assert_eq!(wire[0], PREFIX_BITCOIN_TAPROOT);
        assert_eq!(wire.len(), 33);

        let decoded = NobleAddress::from_wire_bytes(&wire).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn from_noble_public_key() {
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let pk = NoblePublicKey::Secp256k1(pk_bytes.clone());
        let addr: NobleAddress = pk.clone().into();
        assert_eq!(addr, NobleAddress::Noble(pk));
    }

    #[test]
    fn empty_wire_bytes_error() {
        assert!(NobleAddress::from_wire_bytes(&[]).is_err());
    }

    #[test]
    fn unknown_prefix_error() {
        assert!(NobleAddress::from_wire_bytes(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn wrong_hash160_length() {
        let mut wire = vec![PREFIX_BITCOIN_HASH160];
        wire.extend_from_slice(&[0u8; 10]);
        assert!(NobleAddress::from_wire_bytes(&wire).is_err());
    }

    #[test]
    fn wrong_taproot_length() {
        let mut wire = vec![PREFIX_BITCOIN_TAPROOT];
        wire.extend_from_slice(&[0u8; 16]);
        assert!(NobleAddress::from_wire_bytes(&wire).is_err());
    }

    #[test]
    fn address_type_names() {
        let (_, pk) = secp256k1::generate_keypair();
        assert_eq!(
            NobleAddress::Noble(NoblePublicKey::Secp256k1(pk)).address_type(),
            "secp256k1"
        );
        assert_eq!(
            NobleAddress::BitcoinHash160([0; 20]).address_type(),
            "bitcoin_hash160"
        );
        assert_eq!(
            NobleAddress::BitcoinTaproot([0; 32]).address_type(),
            "bitcoin_taproot"
        );
    }

    #[test]
    fn hash_eq_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let addr1 = NobleAddress::BitcoinHash160([0xab; 20]);
        let addr2 = NobleAddress::BitcoinHash160([0xab; 20]);
        let addr3 = NobleAddress::BitcoinHash160([0xcd; 20]);

        let mut h1 = DefaultHasher::new();
        addr1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        addr2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());

        let mut h3 = DefaultHasher::new();
        addr3.hash(&mut h3);
        assert_ne!(h1.finish(), h3.finish());
    }

    #[test]
    fn to_hex_format() {
        let addr = NobleAddress::BitcoinHash160([0xab; 20]);
        let hex_str = addr.to_hex();
        assert!(hex_str.starts_with("80"));
        assert_eq!(hex_str.len(), 42);
    }

    #[test]
    fn bitcoin_hash160_for_secp256k1() {
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let pk = NoblePublicKey::Secp256k1(pk_bytes);
        let btc_addr = NobleAddress::bitcoin_hash160_for_pubkey(&pk);
        assert!(btc_addr.is_some());
        assert_eq!(btc_addr.unwrap().address_type(), "bitcoin_hash160");
    }

    #[test]
    fn bitcoin_taproot_for_secp256k1() {
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let pk = NoblePublicKey::Secp256k1(pk_bytes.clone());
        let tap_addr = NobleAddress::bitcoin_taproot_for_pubkey(&pk);
        assert!(tap_addr.is_some());
        let tap = tap_addr.unwrap();
        assert_eq!(tap.address_type(), "bitcoin_taproot");
        assert_eq!(tap.data_bytes().len(), 32);
        let compressed: [u8; 33] = pk_bytes.as_slice().try_into().unwrap();
        let expected = noble_crypto::bitcoin_addr::taproot_tweak_pubkey(&compressed).unwrap();
        assert_eq!(tap.data_bytes(), &expected[..]);
    }
}
