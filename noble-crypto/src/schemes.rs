// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Signature scheme identifiers used throughout the NOBLE protocol.

/// Ed25519 signature scheme identifier.
pub const SCHEME_ED25519: u8 = 0x01;

/// secp256k1 (ECDSA) signature scheme identifier.
pub const SCHEME_SECP256K1: u8 = 0x02;

/// Check whether a scheme ID is recognized by the protocol.
pub fn is_recognized_scheme(scheme_id: u8) -> bool {
    matches!(scheme_id, SCHEME_ED25519 | SCHEME_SECP256K1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_schemes() {
        assert!(is_recognized_scheme(SCHEME_ED25519));
        assert!(is_recognized_scheme(SCHEME_SECP256K1));
    }

    #[test]
    fn unrecognized_scheme() {
        assert!(!is_recognized_scheme(0x00));
        assert!(!is_recognized_scheme(0x03));
        assert!(!is_recognized_scheme(0xFF));
    }
}
