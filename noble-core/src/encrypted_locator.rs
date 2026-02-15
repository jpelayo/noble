// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Encrypted document locators and external attestations for NOBLE notarization transactions.
//!
//! - [`EncryptedLocator`]: A URL or payload encrypted for one or more recipients using hybrid ECIES.
//! - [`ExternalAttestation`]: An opaque external PKI signature (S/MIME, PKCS#7, PGP, etc.).
//!
//! Both are optional fields on [`Transaction`](crate::transaction::Transaction) and are only
//! valid on notarization transactions (`tx_type = 0x00`). The protocol stores them as opaque
//! bytes — all cryptographic validation is a client software concern.

use noble_crypto::NoblePublicKey;
use serde::{Deserialize, Serialize};

/// Encrypted document locator — a payload (URL, IPFS CID, file path, etc.)
/// encrypted for one or more recipients using hybrid ECIES.
///
/// The protocol treats the encrypted payload as opaque bytes. URL format/length
/// validation is a client concern. Transaction size is bounded by `MAX_TX_SIZE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedLocator {
    /// AES-256-GCM encrypted payload (the URL/locator data).
    pub ciphertext: Vec<u8>,
    /// GCM nonce for the payload encryption (12 bytes).
    pub nonce: [u8; 12],
    /// Per-recipient key envelopes.
    pub recipients: Vec<LocatorRecipient>,
}

/// A recipient's key envelope — the data encryption key encrypted to this recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorRecipient {
    /// Recipient's public key (must be a NOBLE wallet key).
    pub recipient: NoblePublicKey,
    /// Ephemeral public key used for ECDH (X25519 32 bytes or SEC1 33 bytes).
    pub ephemeral_pubkey: Vec<u8>,
    /// AES-256-GCM encrypted data key (32 key bytes + 16 GCM tag = 48 bytes).
    pub encrypted_key: Vec<u8>,
    /// GCM nonce for the key encryption (12 bytes).
    pub key_nonce: [u8; 12],
}

/// An external attestation using a standard PKI signature scheme.
///
/// The protocol stores these as opaque bytes — all validation (certificate chains,
/// revocation, trust anchors) is a client software concern. The node never interprets
/// `signature_data` or verifies the attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAttestation {
    /// Scheme identifier string: "pkcs7", "smime", "pgp", "x509", "xmldsig", etc.
    pub scheme: String,
    /// What this signature covers: "hash", "locator", or "both".
    pub scope: String,
    /// SHA-256 fingerprint of the signer's certificate or key (32 bytes).
    /// Client software resolves the full certificate out-of-band.
    pub signer_fingerprint: [u8; 32],
    /// The raw detached signature bytes. Opaque to the protocol.
    pub signature_data: Vec<u8>,
}
