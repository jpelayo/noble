// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Signature scheme identifiers used throughout the NOBLE protocol.

/// secp256k1 (ECDSA) signature scheme identifier.
pub const SCHEME_SECP256K1: u8 = 0x02;

/// BIP-137 Bitcoin Signed Message recoverable signature scheme identifier.
pub const SCHEME_BIP137: u8 = 0x03;

// --- Internal (non-signing) scheme IDs (0x80+) ---
// These are used for keystore storage of secrets that don't produce on-chain signatures.

/// Validator signing key stored as secp256k1 (block proposal + vote signing).
pub const SCHEME_VALIDATOR_SECP256K1: u8 = 0x81;

/// libp2p identity key (protobuf-encoded keypair bytes).
pub const SCHEME_P2P_IDENTITY: u8 = 0x82;

/// TLS private key (raw PKCS#8 DER bytes).
pub const SCHEME_TLS_KEY: u8 = 0x83;

/// TOTP shared secret (raw bytes, base32-encoded when displayed).
pub const SCHEME_TOTP_SECRET: u8 = 0x84;

/// Faucet keystore passphrase (random 32 bytes, hex-encoded when passed via CLI).
pub const SCHEME_FAUCET_PASSPHRASE: u8 = 0x85;

/// Faucet admin bearer token (random 32 bytes, hex-encoded to 64 chars).
/// Owned by the node, displayed/rotated in the Faucet settings panel,
/// consumed by the faucet binary via `noble_getFaucetAdminToken` RPC.
/// Gates all faucet HTTP admin endpoints (e.g. `/api/faucet/reset-limits`).
pub const SCHEME_FAUCET_ADMIN_TOKEN: u8 = 0x86;

/// Check whether a scheme ID is recognized by the protocol (on-chain or internal).
pub fn is_recognized_scheme(scheme_id: u8) -> bool {
    matches!(
        scheme_id,
            | SCHEME_SECP256K1
            | SCHEME_BIP137
            | SCHEME_VALIDATOR_SECP256K1
            | SCHEME_P2P_IDENTITY
            | SCHEME_TLS_KEY
            | SCHEME_TOTP_SECRET
            | SCHEME_FAUCET_PASSPHRASE
            | SCHEME_FAUCET_ADMIN_TOKEN
    )
}

/// Check whether a scheme ID is an on-chain signing scheme (produces transaction/block signatures).
pub fn is_signing_scheme(scheme_id: u8) -> bool {
    matches!(scheme_id, SCHEME_SECP256K1 | SCHEME_BIP137)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_and_recognized_agree_over_every_u8() {
        // L21/L22: on-chain signature checks (T5 issuer, T7 additional, B12
        // validator) and the ValidatorSchemeUnrecognized evidence predicate must
        // all ask the SAME question, or they disagree about which schemes are
        // valid. They previously split: some used `is_recognized_scheme`, which
        // also admits internal keystore ids (TLS key, TOTP secret, faucet
        // token) that can never produce an on-chain signature — so such a
        // transaction passed the scheme check and only failed one step later,
        // and evidence claiming "unrecognized validator scheme" disagreed with
        // the block rule.
        for id in 0u8..=255 {
            let signing = is_signing_scheme(id);
            let recognized = is_recognized_scheme(id);

            // Exactly two schemes may sign on-chain.
            assert_eq!(
                signing,
                id == SCHEME_SECP256K1 || id == SCHEME_BIP137,
                "scheme {id:#04x}: unexpected signing classification"
            );
            // Signing implies recognized; the converse must NOT hold.
            if signing {
                assert!(recognized, "scheme {id:#04x}: signing but not recognized");
            }
        }

        // The internal ids are the ones that must be recognized yet unable to sign.
        for internal in [
            SCHEME_VALIDATOR_SECP256K1,
            SCHEME_P2P_IDENTITY,
            SCHEME_TLS_KEY,
            SCHEME_TOTP_SECRET,
            SCHEME_FAUCET_PASSPHRASE,
            SCHEME_FAUCET_ADMIN_TOKEN,
        ] {
            assert!(is_recognized_scheme(internal));
            assert!(
                !is_signing_scheme(internal),
                "internal scheme {internal:#04x} must never satisfy an on-chain signature check"
            );
        }
    }

    #[test]
    fn recognized_schemes() {
        assert!(is_recognized_scheme(SCHEME_SECP256K1));
        assert!(is_recognized_scheme(SCHEME_BIP137));
        assert!(is_recognized_scheme(SCHEME_VALIDATOR_SECP256K1));
        assert!(is_recognized_scheme(SCHEME_P2P_IDENTITY));
        assert!(is_recognized_scheme(SCHEME_TLS_KEY));
        assert!(is_recognized_scheme(SCHEME_TOTP_SECRET));
        assert!(is_recognized_scheme(SCHEME_FAUCET_PASSPHRASE));
        assert!(is_recognized_scheme(SCHEME_FAUCET_ADMIN_TOKEN));
    }

    #[test]
    fn unrecognized_scheme() {
        assert!(!is_recognized_scheme(0x00));
        assert!(!is_recognized_scheme(0x04));
        assert!(!is_recognized_scheme(0x87));
        assert!(!is_recognized_scheme(0xFF));
    }

    #[test]
    fn signing_schemes() {
        assert!(is_signing_scheme(SCHEME_SECP256K1));
        assert!(is_signing_scheme(SCHEME_BIP137));
        assert!(!is_signing_scheme(SCHEME_VALIDATOR_SECP256K1));
        assert!(!is_signing_scheme(SCHEME_P2P_IDENTITY));
        assert!(!is_signing_scheme(SCHEME_TLS_KEY));
        assert!(!is_signing_scheme(SCHEME_TOTP_SECRET));
    }
}
