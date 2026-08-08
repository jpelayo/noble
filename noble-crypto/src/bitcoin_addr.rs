// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin address parsing, derivation, and encoding.
//!
//! Supports P2PKH (`1...`), P2WPKH (`bc1q...`), and P2TR (`bc1p...`) addresses.
//! Used by the dual-address system to let operators paste Bitcoin addresses directly.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Bitcoin address type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinAddressType {
    /// P2PKH — Base58Check, version 0x00 (mainnet) or 0x6f (testnet)
    P2pkh,
    /// P2WPKH — Bech32, witness v0, 20-byte program
    P2wpkh,
    /// P2TR — Bech32m, witness v1, 32-byte program
    P2tr,
}

/// Result of parsing a Bitcoin address.
#[derive(Debug, Clone)]
pub struct ParsedBitcoinAddress {
    pub address_type: BitcoinAddressType,
    /// For Hash160 types (P2PKH, P2WPKH): 20 bytes. For Taproot: 32 bytes.
    pub data: Vec<u8>,
    /// Whether this is a mainnet address.
    pub mainnet: bool,
}

/// Errors from Bitcoin address operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BitcoinAddrError {
    #[error("invalid base58check: {0}")]
    InvalidBase58(String),
    #[error("invalid bech32: {0}")]
    InvalidBech32(String),
    #[error("unsupported address format: {0}")]
    UnsupportedFormat(String),
    #[error("invalid witness program length: expected {expected}, got {got}")]
    InvalidWitnessLength { expected: usize, got: usize },
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("P2SH addresses (3...) are not supported — they contain script hashes, not public keys")]
    P2shNotSupported,
    #[error("invalid WIF key: {0}")]
    InvalidWif(String),
    #[error("testnet addresses not supported; use a mainnet Bitcoin address")]
    TestnetNotSupported,
}

/// Compute RIPEMD160(SHA256(data)) — the Bitcoin Hash160 function.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha_hash = Sha256::digest(data);
    let ripe_hash = Ripemd160::digest(sha_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripe_hash);
    result
}

/// Derive a P2PKH address (`1...`) from a compressed secp256k1 public key.
pub fn pubkey_to_p2pkh(compressed: &[u8; 33], mainnet: bool) -> String {
    let h160 = hash160(compressed);
    let version = if mainnet { 0x00 } else { 0x6f };
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(&h160);
    bs58::encode(payload).with_check().into_string()
}

/// Derive a P2WPKH address (`bc1q...`) from a compressed secp256k1 public key.
pub fn pubkey_to_p2wpkh(compressed: &[u8; 33], mainnet: bool) -> String {
    let h160 = hash160(compressed);
    let hrp = if mainnet {
        bech32::Hrp::parse("bc").unwrap()
    } else {
        bech32::Hrp::parse("tb").unwrap()
    };
    encode_segwit(hrp, 0, &h160)
}

/// Derive a P2TR address (`bc1p...`) from a compressed secp256k1 public key.
///
/// Applies the BIP-341 key-path-only tweak: `Q = P + tagged_hash("TapTweak", x(P)) · G`
/// and encodes the tweaked x-only output key as a Bech32m address.
pub fn pubkey_to_p2tr(compressed: &[u8; 33], mainnet: bool) -> String {
    // Never panics: this is a formatting path reached from RPC responses and
    // CLI output, and the 33 bytes are not guaranteed to be a valid curve
    // point (they can arrive from decoded/stored material). A key that cannot
    // be tweaked renders as a clearly-invalid placeholder instead of aborting
    // the process. Callers that need to distinguish should use
    // [`try_pubkey_to_p2tr`].
    try_pubkey_to_p2tr(compressed, mainnet)
        .unwrap_or_else(|| INVALID_ADDRESS_PLACEHOLDER.to_string())
}

/// Rendered in place of an address that cannot be derived. Deterministic and
/// syntactically invalid as an address, so it can never be mistaken for one.
pub const INVALID_ADDRESS_PLACEHOLDER: &str = "<invalid-key>";

/// Fallible form of [`pubkey_to_p2tr`]: `None` when `compressed` is not a valid
/// secp256k1 point and therefore has no Taproot output key.
pub fn try_pubkey_to_p2tr(compressed: &[u8; 33], mainnet: bool) -> Option<String> {
    let output_key = taproot_tweak_pubkey(compressed)?;
    // HRPs are compile-time constants, so these parses cannot fail.
    let hrp = if mainnet {
        bech32::Hrp::parse("bc").expect("const HRP")
    } else {
        bech32::Hrp::parse("tb").expect("const HRP")
    };
    Some(encode_segwit(hrp, 1, &output_key))
}

/// Derive the BIP-341 Taproot output key from a compressed secp256k1 public key.
///
/// Applies the key-path-only tweak (no script tree):
/// `Q = P + tagged_hash("TapTweak", x_only(P)) · G`
///
/// Returns the 32-byte x-only output key (even Y), or `None` if the tweak is invalid.
pub fn taproot_tweak_pubkey(compressed: &[u8; 33]) -> Option<[u8; 32]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use k256::{ProjectivePoint, PublicKey, Scalar};

    // 1. Extract x-only (internal key)
    let xonly = &compressed[1..];

    // 2. Compute tweak: t = tagged_hash("TapTweak", xonly)
    let t_hash = crate::hash::tagged_hash("TapTweak", xonly);

    // 3. Parse tweak as scalar (fails if t >= curve order)
    let t_repr = k256::FieldBytes::from_slice(t_hash.as_bytes());
    let t: Scalar = Option::from(Scalar::from_repr(*t_repr))?;

    // 4. lift_x: parse x-only as point with even Y (0x02 prefix)
    let mut even_compressed = [0u8; 33];
    even_compressed[0] = 0x02;
    even_compressed[1..].copy_from_slice(xonly);
    let p = PublicKey::from_sec1_bytes(&even_compressed).ok()?;
    let p_proj: ProjectivePoint = p.to_projective();

    // 5. Q = P + t·G
    let q = p_proj + ProjectivePoint::GENERATOR * t;

    // 6. Extract x-only from Q (always even Y per BIP-341 convention)
    let q_affine = q.to_affine();
    let q_point = q_affine.to_encoded_point(false);
    let q_x = q_point.x()?;

    let mut output = [0u8; 32];
    output.copy_from_slice(q_x.as_slice());
    Some(output)
}

/// Parse a Bitcoin address string into its components.
///
/// Accepts: P2PKH (`1...`), P2WPKH (`bc1q...`), P2TR (`bc1p...`).
/// Rejects: P2SH (`3...`) — script hashes, not public keys.
pub fn parse_bitcoin_address(addr: &str) -> Result<ParsedBitcoinAddress, BitcoinAddrError> {
    let trimmed = addr.trim();

    // Bech32/Bech32m addresses (bc1... or tb1...)
    if trimmed.starts_with("bc1") || trimmed.starts_with("BC1") {
        return parse_bech32(trimmed, true);
    }
    if trimmed.starts_with("tb1") || trimmed.starts_with("TB1") {
        return Err(BitcoinAddrError::TestnetNotSupported);
    }

    // Base58Check addresses
    if trimmed.starts_with('1') {
        return parse_base58_p2pkh(trimmed);
    }
    // Testnet P2PKH addresses (m... or n...)
    if trimmed.starts_with('m') || trimmed.starts_with('n') {
        return Err(BitcoinAddrError::TestnetNotSupported);
    }
    if trimmed.starts_with('3') || trimmed.starts_with('2') {
        return Err(BitcoinAddrError::P2shNotSupported);
    }

    Err(BitcoinAddrError::UnsupportedFormat(format!(
        "unrecognized address prefix: {}",
        &trimmed[..trimmed.len().min(4)]
    )))
}

/// Encode a segwit address using the bech32 segwit module.
fn encode_segwit(hrp: bech32::Hrp, witness_version: u8, program: &[u8]) -> String {
    let ver = bech32::Fe32::try_from(witness_version).unwrap();
    bech32::segwit::encode(hrp, ver, program).unwrap()
}

/// Parse a bech32/bech32m encoded segwit address.
fn parse_bech32(addr: &str, mainnet: bool) -> Result<ParsedBitcoinAddress, BitcoinAddrError> {
    let (hrp, version, program) = bech32::segwit::decode(addr)
        .map_err(|e| BitcoinAddrError::InvalidBech32(e.to_string()))?;

    let expected_hrp = if mainnet { "bc" } else { "tb" };
    if hrp.as_str() != expected_hrp {
        return Err(BitcoinAddrError::InvalidBech32(format!(
            "unexpected HRP: {}",
            hrp
        )));
    }

    let witness_version = version.to_u8();

    match witness_version {
        0 => {
            if program.len() != 20 {
                return Err(BitcoinAddrError::InvalidWitnessLength {
                    expected: 20,
                    got: program.len(),
                });
            }
            Ok(ParsedBitcoinAddress {
                address_type: BitcoinAddressType::P2wpkh,
                data: program,
                mainnet,
            })
        }
        1 => {
            if program.len() != 32 {
                return Err(BitcoinAddrError::InvalidWitnessLength {
                    expected: 32,
                    got: program.len(),
                });
            }
            Ok(ParsedBitcoinAddress {
                address_type: BitcoinAddressType::P2tr,
                data: program,
                mainnet,
            })
        }
        v => Err(BitcoinAddrError::UnsupportedFormat(format!(
            "unsupported witness version: {v}"
        ))),
    }
}

/// Parse a Base58Check P2PKH address.
fn parse_base58_p2pkh(addr: &str) -> Result<ParsedBitcoinAddress, BitcoinAddrError> {
    let decoded = bs58::decode(addr)
        .with_check(None)
        .into_vec()
        .map_err(|e| BitcoinAddrError::InvalidBase58(e.to_string()))?;

    if decoded.len() != 21 {
        return Err(BitcoinAddrError::InvalidBase58(format!(
            "expected 21 bytes, got {}",
            decoded.len()
        )));
    }

    let version = decoded[0];
    let mainnet = match version {
        0x00 => true,  // mainnet P2PKH
        0x6f => false, // testnet P2PKH
        v => {
            return Err(BitcoinAddrError::UnsupportedFormat(format!(
                "unknown Base58Check version: 0x{v:02x}"
            )));
        }
    };

    Ok(ParsedBitcoinAddress {
        address_type: BitcoinAddressType::P2pkh,
        data: decoded[1..].to_vec(),
        mainnet,
    })
}

/// Encode a Hash160 as a P2WPKH bech32 address for display.
pub fn hash160_to_p2wpkh(hash: &[u8; 20], mainnet: bool) -> String {
    let hrp = if mainnet {
        bech32::Hrp::parse("bc").unwrap()
    } else {
        bech32::Hrp::parse("tb").unwrap()
    };
    encode_segwit(hrp, 0, hash)
}

/// Encode a 32-byte x-only key as a P2TR bech32m address for display.
pub fn xonly_to_p2tr(xonly: &[u8; 32], mainnet: bool) -> String {
    let hrp = if mainnet {
        bech32::Hrp::parse("bc").unwrap()
    } else {
        bech32::Hrp::parse("tb").unwrap()
    };
    encode_segwit(hrp, 1, xonly)
}

/// Decode a WIF (Wallet Import Format) private key to raw 32-byte secret.
/// Accepts both compressed (34 payload) and uncompressed (33 payload) WIF.
pub fn decode_wif(wif: &str) -> Result<Vec<u8>, BitcoinAddrError> {
    let decoded = bs58::decode(wif)
        .with_check(None)
        .into_vec()
        .map_err(|e| BitcoinAddrError::InvalidWif(e.to_string()))?;

    match decoded.len() {
        // Uncompressed: [version(1) + key(32)] = 33 bytes (after checksum strip)
        33 => Ok(decoded[1..33].to_vec()),
        // Compressed: [version(1) + key(32) + compression_flag(1)] = 34 bytes
        34 => {
            if decoded[33] != 0x01 {
                return Err(BitcoinAddrError::InvalidWif("bad compression flag".into()));
            }
            Ok(decoded[1..33].to_vec())
        }
        other => Err(BitcoinAddrError::InvalidWif(format!(
            "unexpected length {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_known_vector() {
        // Hash160 of a known input
        let data = b"hello";
        let h = hash160(data);
        assert_eq!(h.len(), 20);
        // SHA256("hello") = 2cf24d...
        // RIPEMD160(SHA256("hello")) = b6a9c8c230bb...
        let hex_str = hex::encode(h);
        assert_eq!(hex_str, "b6a9c8c230722b7c748331a8b450f05566dc7d0f");
    }

    #[test]
    fn p2pkh_derivation() {
        // Known compressed pubkey (Bitcoin wiki test vector)
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let addr = pubkey_to_p2pkh(&key, true);
        assert!(addr.starts_with('1'), "P2PKH must start with 1: {addr}");
        // Known result: 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs
        assert_eq!(addr, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
    }

    #[test]
    fn p2wpkh_derivation() {
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let addr = pubkey_to_p2wpkh(&key, true);
        assert!(addr.starts_with("bc1q"), "P2WPKH must start with bc1q: {addr}");
        assert_eq!(addr.len(), 42, "P2WPKH mainnet must be 42 chars");
    }

    #[test]
    fn p2tr_derivation() {
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let addr = pubkey_to_p2tr(&key, true);
        assert!(addr.starts_with("bc1p"), "P2TR must start with bc1p: {addr}");
        assert_eq!(addr.len(), 62, "P2TR mainnet must be 62 chars");
    }

    #[test]
    fn p2pkh_and_p2wpkh_share_hash160() {
        // P2PKH and P2WPKH for the same pubkey use the same Hash160
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let h = hash160(&compressed);

        let p2pkh_addr = pubkey_to_p2pkh(&compressed.as_slice().try_into().unwrap(), true);
        let p2wpkh_addr = pubkey_to_p2wpkh(&compressed.as_slice().try_into().unwrap(), true);

        // Parse both — they should yield the same Hash160
        let parsed_p2pkh = parse_bitcoin_address(&p2pkh_addr).unwrap();
        let parsed_p2wpkh = parse_bitcoin_address(&p2wpkh_addr).unwrap();

        assert_eq!(parsed_p2pkh.data, h.to_vec());
        assert_eq!(parsed_p2wpkh.data, h.to_vec());
        assert_eq!(parsed_p2pkh.data, parsed_p2wpkh.data, "P2PKH and P2WPKH must share Hash160");
    }

    #[test]
    fn parse_p2pkh_mainnet() {
        let parsed = parse_bitcoin_address("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs").unwrap();
        assert_eq!(parsed.address_type, BitcoinAddressType::P2pkh);
        assert!(parsed.mainnet);
        assert_eq!(parsed.data.len(), 20);
    }

    #[test]
    fn parse_p2wpkh_mainnet() {
        // BIP-173 test vector: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        let parsed =
            parse_bitcoin_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(parsed.address_type, BitcoinAddressType::P2wpkh);
        assert!(parsed.mainnet);
        assert_eq!(parsed.data.len(), 20);
        let expected_program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(parsed.data, expected_program);
    }

    #[test]
    fn parse_p2tr_mainnet() {
        // BIP-350 test vector
        let parsed = parse_bitcoin_address(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        )
        .unwrap();
        assert_eq!(parsed.address_type, BitcoinAddressType::P2tr);
        assert!(parsed.mainnet);
        assert_eq!(parsed.data.len(), 32);
    }

    #[test]
    fn parse_p2sh_rejected() {
        let result = parse_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
        assert!(result.is_err());
        match result.unwrap_err() {
            BitcoinAddrError::P2shNotSupported => {}
            e => panic!("expected P2shNotSupported, got: {e}"),
        }
    }

    #[test]
    fn parse_invalid_address() {
        assert!(parse_bitcoin_address("not_an_address").is_err());
        assert!(parse_bitcoin_address("").is_err());
    }

    #[test]
    fn hash160_display_roundtrip() {
        let hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let mut h = [0u8; 20];
        h.copy_from_slice(&hash);

        let addr = hash160_to_p2wpkh(&h, true);
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        // Parse it back
        let parsed = parse_bitcoin_address(&addr).unwrap();
        assert_eq!(parsed.data, hash);
    }

    #[test]
    fn xonly_display_roundtrip() {
        let xonly_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let xonly_bytes = hex::decode(xonly_hex).unwrap();
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&xonly_bytes);

        let addr = xonly_to_p2tr(&xonly, true);
        assert!(addr.starts_with("bc1p"));

        let parsed = parse_bitcoin_address(&addr).unwrap();
        assert_eq!(parsed.data, xonly_bytes);
    }

    #[test]
    fn testnet_addresses() {
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let p2pkh = pubkey_to_p2pkh(&key, false);
        assert!(p2pkh.starts_with('m') || p2pkh.starts_with('n'));

        let p2wpkh = pubkey_to_p2wpkh(&key, false);
        assert!(p2wpkh.starts_with("tb1q"));

        let p2tr = pubkey_to_p2tr(&key, false);
        assert!(p2tr.starts_with("tb1p"));
    }

    // --- Finding 4: Testnet address rejection ---

    #[test]
    fn testnet_bech32_address_rejected() {
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let tb1q = pubkey_to_p2wpkh(&key, false);
        let result = parse_bitcoin_address(&tb1q);
        assert!(
            matches!(result, Err(BitcoinAddrError::TestnetNotSupported)),
            "tb1q address should be rejected: {result:?}"
        );

        let tb1p = pubkey_to_p2tr(&key, false);
        let result = parse_bitcoin_address(&tb1p);
        assert!(
            matches!(result, Err(BitcoinAddrError::TestnetNotSupported)),
            "tb1p address should be rejected: {result:?}"
        );
    }

    #[test]
    fn testnet_base58_address_rejected() {
        let compressed = hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let p2pkh_testnet = pubkey_to_p2pkh(&key, false);
        let result = parse_bitcoin_address(&p2pkh_testnet);
        assert!(
            matches!(result, Err(BitcoinAddrError::TestnetNotSupported)),
            "testnet P2PKH should be rejected: {result:?}"
        );
    }

    // --- Finding 2D: WIF decode ---

    #[test]
    fn decode_wif_compressed() {
        // Known test vector: Bitcoin wiki WIF example (compressed)
        // Private key (hex): 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        let wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        let result = decode_wif(wif).unwrap();
        assert_eq!(result.len(), 32);
        let expected = hex::decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_wif_uncompressed() {
        // Same private key in uncompressed WIF format
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let result = decode_wif(wif).unwrap();
        assert_eq!(result.len(), 32);
        let expected = hex::decode("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
        assert_eq!(result, expected);
    }

    // --- BIP-341 Taproot tweak ---

    #[test]
    fn taproot_tweak_pubkey_valid() {
        // Any valid compressed key should produce a tweaked output
        let compressed =
            hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
                .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let output = taproot_tweak_pubkey(&key);
        assert!(output.is_some(), "valid key must produce tweaked output");
        let output = output.unwrap();
        // Tweaked key should differ from raw x-only
        assert_ne!(&output[..], &key[1..33], "tweak must change the key");
    }

    #[test]
    fn p2tr_bip341_tweak_vector() {
        // BIP-341 wallet-test-vectors.json: key-path-only (scriptTree = null)
        let internal_hex = "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d";
        let expected_output_hex =
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343";
        let expected_addr = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5";

        let internal = hex::decode(internal_hex).unwrap();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&internal);

        let output = taproot_tweak_pubkey(&compressed).unwrap();
        assert_eq!(hex::encode(output), expected_output_hex);

        let addr = pubkey_to_p2tr(&compressed, true);
        assert_eq!(addr, expected_addr);
    }

    #[test]
    fn p2tr_uses_tweaked_key_not_raw_xonly() {
        // Verify P2TR address uses the tweaked key, not the raw x-only pubkey
        let compressed =
            hex::decode("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
                .unwrap();
        let mut key = [0u8; 33];
        key.copy_from_slice(&compressed);

        let addr = pubkey_to_p2tr(&key, true);
        let parsed = parse_bitcoin_address(&addr).unwrap();

        // The witness program in the address should be the TWEAKED key, not raw x-only
        let raw_xonly = &key[1..33];
        assert_ne!(
            parsed.data.as_slice(),
            raw_xonly,
            "P2TR address must contain tweaked key, not raw x-only"
        );

        let tweaked = taproot_tweak_pubkey(&key).unwrap();
        assert_eq!(
            parsed.data.as_slice(),
            &tweaked[..],
            "P2TR address must contain the BIP-341 tweaked output key"
        );
    }

    #[test]
    fn decode_wif_invalid() {
        // Corrupted WIF
        let result = decode_wif("NotAValidWIF123");
        assert!(result.is_err(), "invalid WIF should be rejected");

        // Empty string
        let result = decode_wif("");
        assert!(result.is_err(), "empty WIF should be rejected");
    }

    // --- L25: taproot display path must never panic ---

    #[test]
    fn pubkey_to_p2tr_never_panics_on_invalid_curve_points() {
        // The 33 bytes are not guaranteed to be a valid secp256k1 point — they
        // can come from decoded wire data or stored material. This is a display
        // path (RPC/CLI), so an untweakable key must render a placeholder
        // rather than abort the process.
        for pattern in [[0x00u8; 33], [0xFFu8; 33], [0x02u8; 33], [0x07u8; 33]] {
            let rendered = pubkey_to_p2tr(&pattern, true); // must not panic
            match try_pubkey_to_p2tr(&pattern, true) {
                Some(addr) => assert_eq!(rendered, addr),
                None => assert_eq!(rendered, INVALID_ADDRESS_PLACEHOLDER),
            }
        }
    }

    #[test]
    fn pubkey_to_p2tr_valid_key_unchanged() {
        let (_sk, pk) = crate::secp256k1::generate_keypair();
        let compressed: [u8; 33] = pk.as_slice().try_into().unwrap();
        let addr = pubkey_to_p2tr(&compressed, true);
        assert!(addr.starts_with("bc1p"), "got {addr}");
        assert_ne!(addr, INVALID_ADDRESS_PLACEHOLDER);
    }
}
