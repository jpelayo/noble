// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Multi-scheme key types and unified signing/verification interface.
//!
//! Supports Ed25519 and secp256k1 through a single API. Public keys
//! use a wire format of `[scheme_id || key_bytes]` (GAP-H11).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::schemes::{
    SCHEME_ED25519, SCHEME_FAUCET_PASSPHRASE, SCHEME_P2P_IDENTITY, SCHEME_SECP256K1,
    SCHEME_TLS_KEY, SCHEME_TOTP_SECRET, SCHEME_VALIDATOR_ED25519, SCHEME_VALIDATOR_SECP256K1,
};
use crate::{ed25519, secp256k1};

/// A public key supporting multiple signature schemes.
///
/// Wire format: `[scheme_id(1 byte) || key_bytes(variable)]` (GAP-H11).
/// Carries the scheme_id intrinsically — no need for a separate field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NoblePublicKey {
    /// Ed25519 public key (32 bytes).
    Ed25519(Vec<u8>),
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
    /// Ed25519 secret key (32 bytes) — on-chain signing (0x01).
    Ed25519(Vec<u8>),
    /// secp256k1 secret key (32 bytes) — on-chain signing (0x02).
    Secp256k1(Vec<u8>),
    /// Validator Ed25519 signing key (32 bytes) — block proposal + votes (0x80).
    ValidatorEd25519(Vec<u8>),
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
            Self::Ed25519(_) => "Ed25519",
            Self::Secp256k1(_) => "Secp256k1",
            Self::ValidatorEd25519(_) => "ValidatorEd25519",
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
            Self::Ed25519(sk) => Self::Ed25519(sk.clone()),
            Self::Secp256k1(sk) => Self::Secp256k1(sk.clone()),
            Self::ValidatorEd25519(sk) => Self::ValidatorEd25519(sk.clone()),
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
            Self::Ed25519(_) => SCHEME_ED25519,
            Self::Secp256k1(_) => SCHEME_SECP256K1,
        }
    }

    /// Return the raw key bytes (without scheme prefix).
    pub fn key_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(b) | Self::Secp256k1(b) => b,
        }
    }

    /// Encode to wire format: `[scheme_id || key_bytes]` (GAP-H11).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(1 + self.key_bytes().len());
        wire.push(self.scheme_id());
        wire.extend_from_slice(self.key_bytes());
        wire
    }

    /// Human-readable address: `nbl1q…` (Ed25519) or `nbl1p…` (secp256k1).
    pub fn to_address(&self) -> String {
        crate::noble_addr::encode(self)
    }

    /// Decode from wire format: `[scheme_id || key_bytes]` (GAP-H11).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidKey("empty wire bytes".to_string()));
        }

        let scheme_id = bytes[0];
        let key_bytes = &bytes[1..];

        match scheme_id {
            SCHEME_ED25519 => {
                if key_bytes.len() != ed25519::PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidKey(format!(
                        "Ed25519 public key: expected {} bytes, got {}",
                        ed25519::PUBLIC_KEY_LEN,
                        key_bytes.len()
                    )));
                }
                Ok(Self::Ed25519(key_bytes.to_vec()))
            }
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
            Self::Ed25519(pk) => ed25519::verify(pk, message, &sig.signature),
            Self::Secp256k1(pk) => secp256k1::verify(pk, message, &sig.signature),
        }
    }
}

impl NoblePrivateKey {
    /// Return the scheme identifier for this key.
    pub fn scheme_id(&self) -> u8 {
        match self {
            Self::Ed25519(_) => SCHEME_ED25519,
            Self::Secp256k1(_) => SCHEME_SECP256K1,
            Self::ValidatorEd25519(_) => SCHEME_VALIDATOR_ED25519,
            Self::ValidatorSecp256k1(_) => SCHEME_VALIDATOR_SECP256K1,
            Self::P2pIdentity(_) => SCHEME_P2P_IDENTITY,
            Self::TlsKey(_) => SCHEME_TLS_KEY,
            Self::TotpSecret(_) => SCHEME_TOTP_SECRET,
            Self::FaucetPassphrase(_) => SCHEME_FAUCET_PASSPHRASE,
        }
    }

    /// Derive the corresponding public key.
    ///
    /// For on-chain signing keys (Ed25519, Secp256k1) and validator keys,
    /// this derives the real public key. For non-signing types (P2P, TLS, TOTP),
    /// returns a synthetic Ed25519 "public key" that is the SHA-256 hash of
    /// the raw bytes — used only as a keystore filename, not for verification.
    pub fn public_key(&self) -> NoblePublicKey {
        match self {
            Self::Ed25519(sk) | Self::ValidatorEd25519(sk) => {
                let signing_key =
                    ed25519_dalek::SigningKey::from_bytes(&sk.as_slice().try_into().unwrap());
                let vk = signing_key.verifying_key();
                NoblePublicKey::Ed25519(vk.to_bytes().to_vec())
            }
            Self::Secp256k1(sk) | Self::ValidatorSecp256k1(sk) => {
                let signing_key = k256::ecdsa::SigningKey::from_slice(sk).unwrap();
                let vk = signing_key.verifying_key();
                NoblePublicKey::Secp256k1(vk.to_sec1_bytes().to_vec())
            }
            Self::P2pIdentity(raw) | Self::TlsKey(raw) | Self::TotpSecret(raw) | Self::FaucetPassphrase(raw) => {
                // Synthetic: SHA-256 of raw bytes, used as keystore filename only.
                let hash = crate::sha256(raw);
                NoblePublicKey::Ed25519(hash.as_bytes().to_vec())
            }
        }
    }

    /// Return the raw secret bytes for non-signing key types.
    ///
    /// For on-chain signing keys, returns `None` — use `sign()` instead.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ed25519(_) | Self::Secp256k1(_) => None,
            Self::ValidatorEd25519(b)
            | Self::ValidatorSecp256k1(b)
            | Self::P2pIdentity(b)
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
            Self::Ed25519(sk) => (SCHEME_ED25519, ed25519::sign(sk, message)?),
            Self::Secp256k1(sk) => (SCHEME_SECP256K1, secp256k1::sign(sk, message)?),
            Self::ValidatorEd25519(sk) => (SCHEME_ED25519, ed25519::sign(sk, message)?),
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
    /// Signature scheme identifier (SCHEME_ED25519 or SCHEME_SECP256K1).
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
            SCHEME_ED25519 => {
                if self.public_key.len() != ed25519::PUBLIC_KEY_LEN {
                    return Err(CryptoError::InvalidKey(format!(
                        "Ed25519 public key: expected {} bytes, got {}",
                        ed25519::PUBLIC_KEY_LEN,
                        self.public_key.len()
                    )));
                }
                if self.signature.len() != ed25519::SIGNATURE_LEN {
                    return Err(CryptoError::VerificationFailed(format!(
                        "Ed25519 signature: expected {} bytes, got {}",
                        ed25519::SIGNATURE_LEN,
                        self.signature.len()
                    )));
                }
            }
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
            SCHEME_ED25519 => ed25519::verify(&self.public_key, message, &self.signature),
            SCHEME_SECP256K1 => secp256k1::verify(&self.public_key, message, &self.signature),
            other => Err(CryptoError::UnknownScheme(other)),
        }
    }

    /// Extract the NoblePublicKey from this envelope.
    pub fn to_noble_public_key(&self) -> Result<NoblePublicKey, CryptoError> {
        match self.scheme_id {
            SCHEME_ED25519 => Ok(NoblePublicKey::Ed25519(self.public_key.clone())),
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
    fn ed25519_keypair_derivation() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        assert_eq!(pub_key.key_bytes(), pk.as_slice());
        assert_eq!(pub_key.scheme_id(), SCHEME_ED25519);
    }

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
    fn ed25519_wire_roundtrip() {
        let (_, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk);
        let wire = pub_key.to_wire_bytes();
        assert_eq!(wire[0], SCHEME_ED25519);
        assert_eq!(wire.len(), 1 + ed25519::PUBLIC_KEY_LEN);

        let decoded = NoblePublicKey::from_wire_bytes(&wire).unwrap();
        assert_eq!(pub_key, decoded);
    }

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
        let mut wire = vec![SCHEME_ED25519];
        wire.extend_from_slice(&[0u8; 16]); // Too short for Ed25519
        assert!(NoblePublicKey::from_wire_bytes(&wire).is_err());
    }

    // --- NobleSigner / NobleVerifier ---

    #[test]
    fn ed25519_sign_verify_through_traits() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();

        let message = sha256(b"trait test message");
        let envelope = priv_key.sign(message.as_bytes()).unwrap();

        assert_eq!(envelope.scheme_id, SCHEME_ED25519);
        assert!(NobleVerifier::verify(&pub_key, message.as_bytes(), &envelope).is_ok());
    }

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
    fn envelope_verify_standalone_ed25519() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let msg = sha256(b"standalone test");
        let envelope = priv_key.sign(msg.as_bytes()).unwrap();
        assert!(envelope.verify_standalone(msg.as_bytes()).is_ok());
    }

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
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let msg = sha256(b"pubkey extraction");
        let envelope = priv_key.sign(msg.as_bytes()).unwrap();

        let extracted = envelope.to_noble_public_key().unwrap();
        assert_eq!(extracted, pub_key);
    }

    // --- Cross-scheme rejection ---

    #[test]
    fn cross_scheme_verification_rejected() {
        let (ed_sk, _) = ed25519::generate_keypair();
        let (_, secp_pk) = secp256k1::generate_keypair();

        let ed_priv = NoblePrivateKey::Ed25519(ed_sk);
        let secp_pub = NoblePublicKey::Secp256k1(secp_pk);

        let msg = sha256(b"cross-scheme");
        let ed_envelope = ed_priv.sign(msg.as_bytes()).unwrap();

        // Trying to verify an Ed25519 signature with a secp256k1 key
        let result = secp_pub.verify(msg.as_bytes(), &ed_envelope);
        assert!(result.is_err(), "cross-scheme verification must fail");
    }

    // --- CBOR serialization ---

    #[test]
    fn signature_envelope_cbor_roundtrip() {
        use noble_codec::NobleCbor;

        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let msg = sha256(b"cbor roundtrip");
        let envelope = priv_key.sign(msg.as_bytes()).unwrap();

        let bytes = envelope.to_cbor().unwrap();
        let decoded = SignatureEnvelope::from_cbor(&bytes).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn noble_public_key_cbor_roundtrip() {
        use noble_codec::NobleCbor;

        let (_, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk);

        let bytes = pub_key.to_cbor().unwrap();
        let decoded = NoblePublicKey::from_cbor(&bytes).unwrap();
        assert_eq!(pub_key, decoded);
    }

    // --- Phase 1 audit remediation tests ---

    #[test]
    fn validator_key_sign_verify() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::ValidatorEd25519(sk);
        let pub_key = priv_key.public_key();

        let message = sha256(b"validator sign test");
        let envelope = priv_key.sign(message.as_bytes()).unwrap();
        // Validator keys sign with the underlying scheme (Ed25519)
        assert_eq!(envelope.scheme_id, SCHEME_ED25519);
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
        let (sk, _) = ed25519::generate_keypair();
        let signing_key = NoblePrivateKey::Ed25519(sk);
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
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
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
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let cloned = priv_key.clone_for_test();
        // Both can derive the same public key
        assert_eq!(priv_key.public_key(), cloned.public_key());
    }

    #[test]
    fn signature_envelope_validate_lengths_ed25519() {
        let envelope = SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        assert!(envelope.validate_lengths().is_ok());

        let bad_pk = SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: vec![0u8; 16], // wrong length
            signature: vec![0u8; 64],
        };
        assert!(bad_pk.validate_lengths().is_err());

        let bad_sig = SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: vec![0u8; 32],
            signature: vec![0u8; 32], // wrong length
        };
        assert!(bad_sig.validate_lengths().is_err());
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

    #[test]
    fn noble_public_key_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let (_, pk1) = ed25519::generate_keypair();
        let key1 = NoblePublicKey::Ed25519(pk1);

        // Same key hashes to the same value
        let mut h1 = DefaultHasher::new();
        key1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        key1.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "same key must produce same hash");

        // Different key hashes to a different value (probabilistic but near-certain)
        let (_, pk2) = ed25519::generate_keypair();
        let key2 = NoblePublicKey::Ed25519(pk2);
        let mut h3 = DefaultHasher::new();
        key2.hash(&mut h3);
        assert_ne!(
            h1.finish(),
            h3.finish(),
            "different keys should produce different hashes"
        );
    }
}
