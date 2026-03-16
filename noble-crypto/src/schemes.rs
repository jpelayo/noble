// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Signature scheme identifiers used throughout the NOBLE protocol.

/// Ed25519 signature scheme identifier.
pub const SCHEME_ED25519: u8 = 0x01;

/// secp256k1 (ECDSA) signature scheme identifier.
pub const SCHEME_SECP256K1: u8 = 0x02;

/// BIP-137 Bitcoin Signed Message recoverable signature scheme identifier.
pub const SCHEME_BIP137: u8 = 0x03;

// --- Internal (non-signing) scheme IDs (0x80+) ---
// These are used for keystore storage of secrets that don't produce on-chain signatures.

/// Validator signing key stored as Ed25519 (block proposal + vote signing).
pub const SCHEME_VALIDATOR_ED25519: u8 = 0x80;

/// Validator signing key stored as secp256k1 (block proposal + vote signing).
pub const SCHEME_VALIDATOR_SECP256K1: u8 = 0x81;

/// libp2p identity key (Ed25519, protobuf-encoded keypair bytes).
pub const SCHEME_P2P_IDENTITY: u8 = 0x82;

/// TLS private key (raw PKCS#8 DER bytes).
pub const SCHEME_TLS_KEY: u8 = 0x83;

/// TOTP shared secret (raw bytes, base32-encoded when displayed).
pub const SCHEME_TOTP_SECRET: u8 = 0x84;

/// Faucet keystore passphrase (random 32 bytes, hex-encoded when passed via CLI).
pub const SCHEME_FAUCET_PASSPHRASE: u8 = 0x85;

/// Check whether a scheme ID is recognized by the protocol (on-chain or internal).
pub fn is_recognized_scheme(scheme_id: u8) -> bool {
    matches!(
        scheme_id,
        SCHEME_ED25519
            | SCHEME_SECP256K1
            | SCHEME_BIP137
            | SCHEME_VALIDATOR_ED25519
            | SCHEME_VALIDATOR_SECP256K1
            | SCHEME_P2P_IDENTITY
            | SCHEME_TLS_KEY
            | SCHEME_TOTP_SECRET
            | SCHEME_FAUCET_PASSPHRASE
    )
}

/// Check whether a scheme ID is an on-chain signing scheme (produces transaction/block signatures).
pub fn is_signing_scheme(scheme_id: u8) -> bool {
    matches!(scheme_id, SCHEME_ED25519 | SCHEME_SECP256K1 | SCHEME_BIP137)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_schemes() {
        assert!(is_recognized_scheme(SCHEME_ED25519));
        assert!(is_recognized_scheme(SCHEME_SECP256K1));
        assert!(is_recognized_scheme(SCHEME_BIP137));
        assert!(is_recognized_scheme(SCHEME_VALIDATOR_ED25519));
        assert!(is_recognized_scheme(SCHEME_VALIDATOR_SECP256K1));
        assert!(is_recognized_scheme(SCHEME_P2P_IDENTITY));
        assert!(is_recognized_scheme(SCHEME_TLS_KEY));
        assert!(is_recognized_scheme(SCHEME_TOTP_SECRET));
        assert!(is_recognized_scheme(SCHEME_FAUCET_PASSPHRASE));
    }

    #[test]
    fn unrecognized_scheme() {
        assert!(!is_recognized_scheme(0x00));
        assert!(!is_recognized_scheme(0x04));
        assert!(!is_recognized_scheme(0x86));
        assert!(!is_recognized_scheme(0xFF));
    }

    #[test]
    fn signing_schemes() {
        assert!(is_signing_scheme(SCHEME_ED25519));
        assert!(is_signing_scheme(SCHEME_SECP256K1));
        assert!(is_signing_scheme(SCHEME_BIP137));
        assert!(!is_signing_scheme(SCHEME_VALIDATOR_ED25519));
        assert!(!is_signing_scheme(SCHEME_VALIDATOR_SECP256K1));
        assert!(!is_signing_scheme(SCHEME_P2P_IDENTITY));
        assert!(!is_signing_scheme(SCHEME_TLS_KEY));
        assert!(!is_signing_scheme(SCHEME_TOTP_SECRET));
    }
}
