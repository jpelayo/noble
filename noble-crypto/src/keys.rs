// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Multi-scheme key types and unified signing/verification interface.
//!
//! use a wire format of `[scheme_id || key_bytes]` (GAP-H11).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::schemes::{
    SCHEME_FAUCET_PASSPHRASE, SCHEME_P2P_IDENTITY, SCHEME_SECP256K1,
    SCHEME_TLS_KEY, SCHEME_TOTP_SECRET, SCHEME_VALIDATOR_SECP256K1,
};
use crate::secp256k1;

/// A public key supporting multiple signature schemes.
///
/// Wire format: `[scheme_id(1 byte) || key_bytes(variable)]` (GAP-H11).
/// Carries the scheme_id intrinsically — no need for a separate field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NoblePublicKey {
    /// Compressed secp256k1 public key (33 bytes).
    Secp256k1(Vec<u8>),
}

/// A private key supporting multiple signature schemes.
///
/// Key material is zeroized on drop (C-1). Clone is intentionally not derived
/// to prevent accidental copies of key material (H-clone).
///
/// Variants 0x01-0x03 are on-chain signing keys. Variants 0x80+ are internal
/// keystore-only secrets that don't produce transaction signatures.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum NoblePrivateKey {
    /// secp256k1 secret key (32 bytes) — on-chain signing (0x02).
    Secp256k1(Vec<u8>),
    /// Validator secp256k1 signing key (32 bytes) — block proposal + votes (0x81).
    ValidatorSecp256k1(Vec<u8>),
    /// libp2p identity key — protobuf-encoded keypair bytes (0x82).
    P2pIdentity(Vec<u8>),
    /// TLS private key — raw PKCS#8 DER bytes (0x83).
    TlsKey(Vec<u8>),
    /// TOTP shared secret — raw bytes (0x84).
    TotpSecret(Vec<u8>),
    /// Faucet keystore passphrase — raw bytes (0x85).
    FaucetPassphrase(Vec<u8>),
}

impl std::fmt::Debug for NoblePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            Self::Secp256k1(_) => "Secp256k1",
            Self::ValidatorSecp256k1(_) => "ValidatorSecp256k1",
            Self::P2pIdentity(_) => "P2pIdentity",
            Self::TlsKey(_) => "TlsKey",
            Self::TotpSecret(_) => "TotpSecret",
            Self::FaucetPassphrase(_) => "FaucetPassphrase",
        };
        write!(f, "NoblePrivateKey::{variant}([REDACTED])")
    }
}

impl NoblePrivateKey {
    /// Create an explicit copy of this private key. Named intentionally to prevent
    /// accidental cloning — use only in tests and when ownership must be shared.
    pub fn clone_for_test(&self) -> Self {
        match self {
            Self::Secp256k1(sk) => Self::Secp256k1(sk.clone()),
            Self::ValidatorSecp256k1(sk) => Self::ValidatorSecp256k1(sk.clone()),
            Self::P2pIdentity(sk) => Self::P2pIdentity(sk.clone()),
            Self::TlsKey(sk) => Self::TlsKey(sk.clone()),
            Self::TotpSecret(sk) => Self::TotpSecret(sk.clone()),
            Self::FaucetPassphrase(sk) => Self::FaucetPassphrase(sk.clone()),
        }
    }
}

impl NoblePublicKey {
    /// Return the scheme identifier for this key.
    pub fn scheme_id(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => SCHEME_SECP256K1,
        }
    }

    /// Return the raw key bytes (without scheme prefix).
    pub fn key_bytes(&self) -> &[u8] {
        match self {
            Self::Secp256k1(bytes) => bytes,
        }
    }

    /// Encode to wire format: `[scheme_id || key_bytes]` (GAP-H11).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(1 + self.key_bytes().len());
        wire.push(self.scheme_id());
        wire.extend_from_slice(self.key_bytes());
        wire
    }

    pub fn to_address(&self) -> String {
        crate::noble_addr::encode(self)
    }

    /// Decode from wire format: `[scheme_id || key_bytes]` (GAP-H11).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKey("empty wire bytes".to_string()));
        }

        // 33 bytes starting with 0x02 or 0x03: raw SEC1 compressed secp256k1 key
        // (not wire format — wire format is 0x02 scheme + 33-byte SEC1 = 34 bytes).
        if bytes.len() == secp256k1::PUBLIC_KEY_LEN && (bytes[0] == 0x02 || bytes[0] == 0x03) {
            return Ok(Self::Secp256k1(bytes.to_vec()));
        }

        let scheme_id = bytes[0];
        let key_bytes = &bytes[1..];

        match scheme_id {
            SCHEME_SECP256K1 => {
                if key_bytes.len() != secp256k1::PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidKey(format!(
                        "secp256k1 public key: expected {} bytes, got {}",
                        secp256k1::PUBLIC_KEY_LEN,
                        key_bytes.len()
                    )));
                }
                Ok(Self::Secp256k1(key_bytes.to_vec()))
            }
            _ => Err(CryptoError::UnknownScheme(scheme_id)),
        }
    }

    /// Verify a signature against this public key.
    pub fn verify(&self, message: &[u8], sig: &SignatureEnvelope) -> Result<(), CryptoError> {
        if sig.scheme_id != self.scheme_id() {
            return Err(CryptoError::VerificationFailed(format!(
                "scheme mismatch: key is {:#04x}, signature is {:#04x}",
                self.scheme_id(),
                sig.scheme_id
            )));
        }

        match self {
            Self::Secp256k1(pk) => secp256k1::verify(pk, message, &sig.signature),
        }
    }
}

impl NoblePrivateKey {
    /// Return the scheme identifier for this key.
    pub fn scheme_id(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => SCHEME_SECP256K1,
            Self::ValidatorSecp256k1(_) => SCHEME_VALIDATOR_SECP256K1,
            Self::P2pIdentity(_) => SCHEME_P2P_IDENTITY,
            Self::TlsKey(_) => SCHEME_TLS_KEY,
            Self::TotpSecret(_) => SCHEME_TOTP_SECRET,
            Self::FaucetPassphrase(_) => SCHEME_FAUCET_PASSPHRASE,
        }
    }

    /// Derive the corresponding public key.
    ///
    /// this derives the real public key. For non-signing types (P2P, TLS, TOTP),
    /// the raw bytes — used only as a keystore filename, not for verification.
    pub fn public_key(&self) -> NoblePublicKey {
        match self {
            Self::Secp256k1(sk) | Self::ValidatorSecp256k1(sk) => {
                let signing_key = k256::ecdsa::SigningKey::from_slice(sk)
                    .expect("secp256k1 secret invalid — keys are validated at creation (OsRng/BIP-32) and GCM-authenticated in the keystore");
                let vk = signing_key.verifying_key();
                NoblePublicKey::Secp256k1(vk.to_sec1_bytes().to_vec())
            }
            Self::P2pIdentity(raw) | Self::TlsKey(raw) | Self::TotpSecret(raw) | Self::FaucetPassphrase(raw) => {
                // Synthetic: SHA-256 of raw bytes → secp256k1 pubkey, used as keystore filename only.
                let hash = crate::sha256(raw);
                let sk = k256::ecdsa::SigningKey::from_slice(&hash.0)
                    .expect("SHA-256 output is a valid secp256k1 scalar (synthetic keystore-filename key)");
                NoblePublicKey::Secp256k1(sk.verifying_key().to_sec1_bytes().to_vec())
            }
        }
    }

    /// Return the raw secret bytes for non-signing key types.
    ///
    /// For on-chain signing keys, returns `None` — use `sign()` instead.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Secp256k1(_) | Self::ValidatorSecp256k1(_) => None,
            Self::P2pIdentity(b)
            | Self::TlsKey(b)
            | Self::TotpSecret(b)
            | Self::FaucetPassphrase(b) => Some(b),
        }
    }
}

/// Unified signing trait for the NOBLE protocol.
///
/// Implementations accept a 32-byte pre-hashed message (the SHA-256
/// of the canonical CBOR signing payload).
pub trait NobleSigner {
    fn sign(&self, message: &[u8; 32]) -> Result<SignatureEnvelope, CryptoError>;
}

/// Unified verification trait for the NOBLE protocol.
pub trait NobleVerifier {
    fn verify(&self, message: &[u8; 32], sig: &SignatureEnvelope) -> Result<(), CryptoError>;
}

impl NobleSigner for NoblePrivateKey {
    fn sign(&self, message: &[u8; 32]) -> Result<SignatureEnvelope, CryptoError> {
        let (sig_scheme_id, signature) = match self {
            Self::Secp256k1(sk) => (SCHEME_SECP256K1, secp256k1::sign(sk, message)?),
            Self::ValidatorSecp256k1(sk) => (SCHEME_SECP256K1, secp256k1::sign(sk, message)?),
            Self::P2pIdentity(_) | Self::TlsKey(_) | Self::TotpSecret(_) | Self::FaucetPassphrase(_) => {
                return Err(CryptoError::VerificationFailed(
                    "non-signing key type cannot produce signatures".to_string(),
                ));
            }
        };

        let public_key = self.public_key();
        Ok(SignatureEnvelope {
            scheme_id: sig_scheme_id,
            public_key: public_key.key_bytes().to_vec(),
            signature,
        })
    }
}

impl NobleVerifier for NoblePublicKey {
    fn verify(&self, message: &[u8; 32], sig: &SignatureEnvelope) -> Result<(), CryptoError> {
        self.verify(message.as_slice(), sig)
    }
}

/// A signature bundled with its scheme identifier and the signer's public key.
///
/// This is the standard signature format used throughout the NOBLE protocol,
/// including `issuer_sig`, `additional_sigs`, and `validator_sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    /// Signature scheme identifier ( or SCHEME_SECP256K1).
    pub scheme_id: u8,
    /// The signer's public key bytes (without scheme prefix).
    pub public_key: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

impl SignatureEnvelope {
    /// Validate that the public_key and signature byte lengths match the declared scheme.
    pub fn validate_lengths(&self) -> Result<(), CryptoError> {
        match self.scheme_id {
            SCHEME_SECP256K1 => {
                if self.public_key.len() != secp256k1::PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidKey(format!(
                        "secp256k1 public key: expected {} bytes, got {}",
                        secp256k1::PUBLIC_KEY_LEN,
                        self.public_key.len()
                    )));
                }
                if self.signature.len() != secp256k1::SIGNATURE_LEN {
                    return Err(CryptoError::VerificationFailed(format!(
                        "secp256k1 signature: expected {} bytes, got {}",
                        secp256k1::SIGNATURE_LEN,
                        self.signature.len()
                    )));
                }
            }
            _ => return Err(CryptoError::UnknownScheme(self.scheme_id)),
        }
        Ok(())
    }

    /// Verify this signature against the provided message, using the embedded public key.
    pub fn verify_standalone(&self, message: &[u8]) -> Result<(), CryptoError> {
        match self.scheme_id {
            SCHEME_SECP256K1 => secp256k1::verify(&self.public_key, message, &self.signature),
            other => Err(CryptoError::UnknownScheme(other)),
        }
    }

    /// Extract the NoblePublicKey from this envelope.
    pub fn to_noble_public_key(&self) -> Result<NoblePublicKey, CryptoError> {
        match self.scheme_id {
            SCHEME_SECP256K1 => Ok(NoblePublicKey::Secp256k1(self.public_key.clone())),
            other => Err(CryptoError::UnknownScheme(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    // --- Key generation and derivation ---

    #[test]
    fn secp256k1_keypair_derivation() {
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();
        assert_eq!(pub_key.key_bytes(), pk.as_slice());
        assert_eq!(pub_key.scheme_id(), SCHEME_SECP256K1);
    }

    // --- Wire format ---

    #[test]
    fn secp256k1_wire_roundtrip() {
        let (_, pk) = secp256k1::generate_keypair();
        let pub_key = NoblePublicKey::Secp256k1(pk);
        let wire = pub_key.to_wire_bytes();
        assert_eq!(wire[0], SCHEME_SECP256K1);
        assert_eq!(wire.len(), 1 + secp256k1::PUBLIC_KEY_LEN);

        let decoded = NoblePublicKey::from_wire_bytes(&wire).unwrap();
        assert_eq!(pub_key, decoded);
    }

    #[test]
    fn wire_format_unknown_scheme() {
        let bad_wire = [0xFF, 0x00, 0x01];
        assert!(NoblePublicKey::from_wire_bytes(&bad_wire).is_err());
    }

    #[test]
    fn wire_format_empty() {
        assert!(NoblePublicKey::from_wire_bytes(&[]).is_err());
    }

    #[test]
    fn wire_format_wrong_key_length() {
        let mut wire = vec![];
        assert!(NoblePublicKey::from_wire_bytes(&wire).is_err());
    }

    // --- NobleSigner / NobleVerifier ---

    #[test]
    fn secp256k1_sign_verify_through_traits() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();

        let message = sha256(b"trait test message");
        let envelope = priv_key.sign(message.as_bytes()).unwrap();

        assert_eq!(envelope.scheme_id, SCHEME_SECP256K1);
        assert!(NobleVerifier::verify(&pub_key, message.as_bytes(), &envelope).is_ok());
    }

    // --- SignatureEnvelope ---

    #[test]
    fn envelope_verify_standalone_secp256k1() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let msg = sha256(b"standalone test");
        let envelope = priv_key.sign(msg.as_bytes()).unwrap();
        assert!(envelope.verify_standalone(msg.as_bytes()).is_ok());
    }

    #[test]
    fn envelope_unknown_scheme_rejected() {
        let envelope = SignatureEnvelope {
            scheme_id: 0xFF,
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        assert!(envelope.verify_standalone(b"test").is_err());
    }

    #[test]
    fn envelope_to_noble_public_key() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();
        let msg = sha256(b"pubkey extraction");
        let envelope = priv_key.sign(msg.as_bytes()).unwrap();

        let extracted = envelope.to_noble_public_key().unwrap();
        assert_eq!(extracted, pub_key);
    }

    // --- Cross-scheme rejection ---


    #[test]
    fn noble_public_key_cbor_roundtrip() {
        use noble_codec::NobleCbor;
        let (_, pk) = secp256k1::generate_keypair();
        let pub_key = NoblePublicKey::Secp256k1(pk);
        let bytes = pub_key.to_cbor().unwrap();
        let decoded = NoblePublicKey::from_cbor(&bytes).unwrap();
        assert_eq!(pub_key, decoded);
    }

    // --- Phase 1 audit remediation tests ---

    #[test]
    fn validator_key_sign_verify() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::ValidatorSecp256k1(sk);
        let pub_key = priv_key.public_key();

        let message = sha256(b"validator sign test");
        let envelope = priv_key.sign(message.as_bytes()).unwrap();
        assert_eq!(envelope.scheme_id, crate::schemes::SCHEME_SECP256K1);
        assert!(pub_key.verify(message.as_bytes(), &envelope).is_ok());
    }

    #[test]
    fn non_signing_key_sign_fails() {
        let priv_key = NoblePrivateKey::P2pIdentity(vec![1, 2, 3]);
        let message = sha256(b"should fail");
        let result = priv_key.sign(message.as_bytes());
        assert!(result.is_err(), "non-signing keys must not produce signatures");
    }

    #[test]
    fn non_signing_key_raw_bytes() {
        let raw = vec![10, 20, 30];
        let priv_key = NoblePrivateKey::TotpSecret(raw.clone());
        assert_eq!(priv_key.raw_bytes(), Some(raw.as_slice()));
        assert_eq!(priv_key.scheme_id(), 0x84);

        // On-chain keys return None
        let (sk, _) = secp256k1::generate_keypair();
        let signing_key = NoblePrivateKey::Secp256k1(sk);
        assert_eq!(signing_key.raw_bytes(), None);
    }

    #[test]
    fn non_signing_key_synthetic_pubkey() {
        let raw = vec![42; 64];
        let key1 = NoblePrivateKey::P2pIdentity(raw.clone());
        let key2 = NoblePrivateKey::P2pIdentity(raw);
        // Same input → same synthetic pubkey
        assert_eq!(key1.public_key(), key2.public_key());

        // Different input → different synthetic pubkey
        let key3 = NoblePrivateKey::TlsKey(vec![99; 64]);
        assert_ne!(key1.public_key(), key3.public_key());
    }

    #[test]
    fn private_key_debug_redacted() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let debug_str = format!("{:?}", priv_key);
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug must not expose key bytes"
        );
        assert!(
            !debug_str.contains("0x"),
            "Debug must not contain hex bytes"
        );
    }

    #[test]
    fn private_key_clone_for_test() {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let cloned = priv_key.clone_for_test();
        assert_eq!(priv_key.public_key(), cloned.public_key());
    }

    #[test]
    fn signature_envelope_validate_lengths_secp256k1() {
        let envelope = SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: vec![0x02; 33],
            signature: vec![0u8; 64],
        };
        assert!(envelope.validate_lengths().is_ok());
    }

    #[test]
    fn signature_envelope_validate_lengths_unknown_scheme() {
        let envelope = SignatureEnvelope {
            scheme_id: 0xFF,
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        assert!(envelope.validate_lengths().is_err());
    }

    // --- from_wire_bytes: 33-byte SEC1 vs 34-byte wire format ---

    #[test]
    fn from_wire_33bytes_sec1_02() {
        // 33 bytes starting with 0x02 = raw SEC1 compressed-even key
        let mut key = vec![0x02];
        key.extend_from_slice(&[0xAB; 32]);
        let pk = NoblePublicKey::from_wire_bytes(&key).unwrap();
        assert_eq!(pk.key_bytes(), key.as_slice());
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);
    }

    #[test]
    fn from_wire_33bytes_sec1_03() {
        // 33 bytes starting with 0x03 = raw SEC1 compressed-odd key
        let mut key = vec![0x03];
        key.extend_from_slice(&[0xCD; 32]);
        let pk = NoblePublicKey::from_wire_bytes(&key).unwrap();
        assert_eq!(pk.key_bytes(), key.as_slice());
    }

    #[test]
    fn from_wire_34bytes_scheme_02() {
        // 34 bytes = 0x02 (scheme) + 33-byte SEC1 key
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let mut wire = vec![SCHEME_SECP256K1];
        wire.extend_from_slice(&pk_bytes);
        assert_eq!(wire.len(), 34);
        let pk = NoblePublicKey::from_wire_bytes(&wire).unwrap();
        assert_eq!(pk.key_bytes(), pk_bytes.as_slice());
    }

    #[test]
    fn from_wire_33bytes_and_34bytes_same_key() {
        // Given a real keypair, both 33-byte (raw SEC1) and 34-byte (wire) produce same key
        let (_, pk_bytes) = secp256k1::generate_keypair();
        let pk_from_33 = NoblePublicKey::from_wire_bytes(&pk_bytes).unwrap();
        let mut wire = vec![SCHEME_SECP256K1];
        wire.extend_from_slice(&pk_bytes);
        let pk_from_34 = NoblePublicKey::from_wire_bytes(&wire).unwrap();
        assert_eq!(pk_from_33, pk_from_34);
    }

    #[test]
    fn from_wire_33bytes_non_sec1_rejected() {
        // 33 bytes starting with 0x80 (Bitcoin Hash160 prefix) — not a valid SEC1 key
        let mut data = vec![0x80];
        data.extend_from_slice(&[0x00; 32]);
        assert!(NoblePublicKey::from_wire_bytes(&data).is_err());
    }

    #[test]
    fn noble_public_key_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let (_, pk1_bytes) = secp256k1::generate_keypair();
        let key1 = NoblePublicKey::Secp256k1(pk1_bytes.clone());
        let (_, pk2_bytes) = secp256k1::generate_keypair();
        let key2 = NoblePublicKey::Secp256k1(pk2_bytes);
        // Same key hashes to the same value
        let mut h1 = DefaultHasher::new();
        key1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        key1.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "same key must produce same hash");

        // Different key hashes to a different value (probabilistic but near-certain)
        let mut h3 = DefaultHasher::new();
        key2.hash(&mut h3);
        assert_ne!(
            h1.finish(),
            h3.finish(),
            "different keys should produce different hashes"
        );
    }
}
