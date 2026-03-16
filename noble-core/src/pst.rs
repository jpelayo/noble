// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Partially Signed Transaction (PST) wire format for multisig and offline signing.
//!
//! A PST wraps an unsigned [`Transaction`] together with a list of expected
//! signers and their collected signatures. Participants pass the PST around,
//! each adding their signature with [`PartiallySignedTransaction::sign`], until
//! [`is_complete`](PartiallySignedTransaction::is_complete) returns `true` and
//! the transaction can be [`finalize`](PartiallySignedTransaction::finalize)d.
//!
//! # File extension
//!
//! The canonical file extension for serialized PSTs is `.noble-pst`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use noble_codec::NobleCbor;
use noble_crypto::{CryptoError, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};

use crate::transaction::Transaction;

/// Current PST wire format version.
pub const PST_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during PST operations.
#[derive(Debug)]
pub enum PstError {
    /// The signing key does not match any entry in the signer list.
    SignerNotFound,
    /// This signer already has a signature attached.
    AlreadySigned,
    /// Cannot finalize: one or more signers have not signed.
    Incomplete,
    /// No signer with role [`SignerRole::Primary`] was added.
    NoPrimarySigner,
    /// CBOR serialization or deserialization error.
    Serialization(String),
    /// Cryptographic operation error (signing or verification).
    Crypto(CryptoError),
}

impl fmt::Display for PstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerNotFound => write!(f, "signer's key not found in PST signer list"),
            Self::AlreadySigned => write!(f, "signer already has a signature attached"),
            Self::Incomplete => write!(f, "cannot finalize: missing signatures"),
            Self::NoPrimarySigner => write!(f, "no primary signer entry in PST"),
            Self::Serialization(msg) => write!(f, "PST serialization error: {msg}"),
            Self::Crypto(e) => write!(f, "PST crypto error: {e}"),
        }
    }
}

impl std::error::Error for PstError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CryptoError> for PstError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<noble_codec::CodecError> for PstError {
    fn from(e: noble_codec::CodecError) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// SignerRole
// ---------------------------------------------------------------------------

/// The role a signer plays in a partially signed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerRole {
    /// The transaction's main signer (must match `Transaction.publisher_sig`).
    Primary,
    /// An additional co-signer (appended to `additional_sigs`).
    Additional,
    /// A witness signature — attestation only, not required for validity.
    Witness,
}

// ---------------------------------------------------------------------------
// SignerEntry
// ---------------------------------------------------------------------------

/// A single signer slot in a PST: expected public key, optional signature, and role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEntry {
    /// The expected signer's public key.
    pub pubkey: NoblePublicKey,
    /// The collected signature, or `None` if this signer has not yet signed.
    pub signature: Option<SignatureEnvelope>,
    /// What role this signer plays.
    pub role: SignerRole,
}

// ---------------------------------------------------------------------------
// PartiallySignedTransaction
// ---------------------------------------------------------------------------

/// A partially signed transaction collecting signatures from multiple parties.
///
/// Create one with [`new`](Self::new), add signers with [`add_signer`](Self::add_signer),
/// have each party call [`sign`](Self::sign), then [`finalize`](Self::finalize) once
/// [`is_complete`](Self::is_complete) returns `true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartiallySignedTransaction {
    /// PST wire format version (currently [`PST_VERSION`]).
    pub version: u8,
    /// The transaction without a primary signature.
    pub unsigned_tx: Transaction,
    /// Collected signer information.
    pub signers: Vec<SignerEntry>,
    /// Unix timestamp (seconds) when the PST was created.
    pub created_at: u64,
    /// Human-readable description of what this PST is for.
    pub description: Option<String>,
}

impl PartiallySignedTransaction {
    /// Create a new PST from an unsigned transaction.
    ///
    /// The transaction's existing `publisher_sig` is preserved as-is (typically
    /// a placeholder with an empty signature). The caller should add signers
    /// with [`add_signer`](Self::add_signer) before distributing the PST.
    pub fn new(tx: Transaction, description: Option<String>) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: PST_VERSION,
            unsigned_tx: tx,
            signers: Vec::new(),
            created_at,
            description,
        }
    }

    /// Add an expected signer to this PST.
    pub fn add_signer(&mut self, pubkey: NoblePublicKey, role: SignerRole) {
        self.signers.push(SignerEntry {
            pubkey,
            signature: None,
            role,
        });
    }

    /// Sign this PST with the given private key and chain ID.
    ///
    /// The key's public key must match one of the signer entries that has not
    /// yet been signed. The signing message is computed from the embedded
    /// transaction using the specified chain_id for replay protection.
    pub fn sign(&mut self, signer: &NoblePrivateKey, chain_id: u32) -> Result<(), PstError> {
        let pub_key = signer.public_key();

        // Find the matching signer entry.
        let entry = self
            .signers
            .iter_mut()
            .find(|e| e.pubkey == pub_key)
            .ok_or(PstError::SignerNotFound)?;

        if entry.signature.is_some() {
            return Err(PstError::AlreadySigned);
        }

        // Compute the signing message from the transaction.
        let msg = self
            .unsigned_tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| PstError::Serialization(e.to_string()))?;

        let envelope = signer.sign(&msg)?;
        entry.signature = Some(envelope);
        Ok(())
    }

    /// Returns `true` if every signer entry has a signature.
    pub fn is_complete(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(|e| e.signature.is_some())
    }

    /// Returns `true` if the primary signer has signed.
    pub fn primary_signed(&self) -> bool {
        self.signers
            .iter()
            .any(|e| e.role == SignerRole::Primary && e.signature.is_some())
    }

    /// Finalize the PST into a fully signed [`Transaction`].
    ///
    /// Fails if any signer entry is missing a signature or if no primary
    /// signer was added.
    pub fn finalize(self) -> Result<Transaction, PstError> {
        if !self.is_complete() {
            return Err(PstError::Incomplete);
        }

        let mut tx = self.unsigned_tx;

        let primary_entry = self
            .signers
            .iter()
            .find(|e| e.role == SignerRole::Primary)
            .ok_or(PstError::NoPrimarySigner)?;

        // Set the publisher signature from the primary signer.
        tx.publisher_sig = primary_entry
            .signature
            .clone()
            .expect("is_complete guarantees Some");

        // Collect additional and witness signatures.
        let additional: Vec<SignatureEnvelope> = self
            .signers
            .iter()
            .filter(|e| e.role != SignerRole::Primary)
            .filter_map(|e| e.signature.clone())
            .collect();

        tx.additional_sigs = additional;

        Ok(tx)
    }

    /// Return the public keys of signers who have not yet signed.
    pub fn unsigned_signers(&self) -> Vec<&NoblePublicKey> {
        self.signers
            .iter()
            .filter(|e| e.signature.is_none())
            .map(|e| &e.pubkey)
            .collect()
    }

    /// Serialize this PST to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PstError> {
        self.to_cbor()
            .map_err(|e| PstError::Serialization(e.to_string()))
    }

    /// Deserialize a PST from CBOR bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PstError> {
        Self::from_cbor(data).map_err(|e| PstError::Serialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::MetadataEntry;
    use crate::utxo::{OutPoint, TxIn};
    use noble_crypto::{ed25519, Hash256, SCHEME_ED25519};

    const TEST_CHAIN_ID: u32 = 0x4E4F424C;

    /// Helper: create an unsigned test transaction and its signing keypair.
    fn make_unsigned_tx() -> (Transaction, NoblePrivateKey, NoblePublicKey) {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let tx = Transaction {
            version: 1,
            tx_type: 0,
            inputs: vec![TxIn {
                prev_output: OutPoint { txid: Hash256::from_bytes([0x01; 32]), vout: 0 },
            }],
            outputs: vec![],
            checksum: Hash256::from_bytes([0xAB; 32]),
            timestamp: 1_700_000_000,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pub_key.key_bytes().to_vec(),
                signature: vec![], // placeholder — unsigned
            },
            additional_sigs: vec![],
            metadata: vec![MetadataEntry {
                key: "doc_type".into(),
                value: b"test_report".to_vec(),
            }],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
        };

        (tx, priv_key, pub_key)
    }

    #[test]
    fn pst_create_and_add_signers() {
        let (tx, _sk, pk) = make_unsigned_tx();

        // Second signer
        let (sk2_raw, pk2_raw) = ed25519::generate_keypair();
        let _sk2 = NoblePrivateKey::Ed25519(sk2_raw);
        let pk2 = NoblePublicKey::Ed25519(pk2_raw);

        let mut pst = PartiallySignedTransaction::new(tx, Some("test PST".into()));

        pst.add_signer(pk.clone(), SignerRole::Primary);
        pst.add_signer(pk2.clone(), SignerRole::Additional);

        assert_eq!(pst.signers.len(), 2);
        assert_eq!(pst.signers[0].role, SignerRole::Primary);
        assert_eq!(pst.signers[1].role, SignerRole::Additional);
        assert_eq!(pst.signers[0].pubkey, pk);
        assert_eq!(pst.signers[1].pubkey, pk2);
        assert!(pst.signers[0].signature.is_none());
        assert!(pst.signers[1].signature.is_none());
        assert!(!pst.is_complete());
        assert!(!pst.primary_signed());
        assert_eq!(pst.unsigned_signers().len(), 2);
        assert_eq!(pst.version, PST_VERSION);
        assert_eq!(pst.description, Some("test PST".into()));
    }

    #[test]
    fn pst_sign_and_complete() {
        let (tx, sk, pk) = make_unsigned_tx();

        let mut pst = PartiallySignedTransaction::new(tx, None);
        pst.add_signer(pk, SignerRole::Primary);

        // Not yet signed.
        assert!(!pst.is_complete());
        assert!(!pst.primary_signed());

        // Sign with primary key.
        pst.sign(&sk, TEST_CHAIN_ID).unwrap();

        assert!(pst.is_complete());
        assert!(pst.primary_signed());
        assert!(pst.unsigned_signers().is_empty());
    }

    #[test]
    fn pst_finalize_produces_valid_tx() {
        let (tx, sk, pk) = make_unsigned_tx();

        let (sk2_raw, pk2_raw) = ed25519::generate_keypair();
        let sk2 = NoblePrivateKey::Ed25519(sk2_raw);
        let pk2 = NoblePublicKey::Ed25519(pk2_raw);

        let mut pst = PartiallySignedTransaction::new(tx, Some("finalize test".into()));
        pst.add_signer(pk.clone(), SignerRole::Primary);
        pst.add_signer(pk2.clone(), SignerRole::Additional);

        pst.sign(&sk, TEST_CHAIN_ID).unwrap();
        pst.sign(&sk2, TEST_CHAIN_ID).unwrap();

        assert!(pst.is_complete());

        let finalized = pst.finalize().unwrap();

        // The publisher_sig should come from the primary signer.
        assert_eq!(finalized.publisher_sig.public_key, pk.key_bytes().to_vec());
        assert!(!finalized.publisher_sig.signature.is_empty());

        // The additional_sigs should contain the second signer.
        assert_eq!(finalized.additional_sigs.len(), 1);
        assert_eq!(
            finalized.additional_sigs[0].public_key,
            pk2.key_bytes().to_vec()
        );

        // Verify the primary signature is valid.
        let msg = finalized.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        pk.verify(&msg, &finalized.publisher_sig).unwrap();
    }

    #[test]
    fn pst_cbor_roundtrip() {
        let (tx, sk, pk) = make_unsigned_tx();

        let (sk2_raw, pk2_raw) = ed25519::generate_keypair();
        let sk2 = NoblePrivateKey::Ed25519(sk2_raw);
        let pk2 = NoblePublicKey::Ed25519(pk2_raw);

        let mut pst = PartiallySignedTransaction::new(tx, Some("roundtrip".into()));
        pst.add_signer(pk, SignerRole::Primary);
        pst.add_signer(pk2, SignerRole::Witness);

        pst.sign(&sk, TEST_CHAIN_ID).unwrap();
        pst.sign(&sk2, TEST_CHAIN_ID).unwrap();

        let bytes = pst.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        let decoded = PartiallySignedTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(pst, decoded);
    }

    #[test]
    fn pst_sign_unknown_key_errors() {
        let (tx, _sk, pk) = make_unsigned_tx();

        let mut pst = PartiallySignedTransaction::new(tx, None);
        pst.add_signer(pk, SignerRole::Primary);

        // Generate a completely unrelated key.
        let (unknown_sk_raw, _) = ed25519::generate_keypair();
        let unknown_sk = NoblePrivateKey::Ed25519(unknown_sk_raw);

        let result = pst.sign(&unknown_sk, TEST_CHAIN_ID);
        assert!(result.is_err());
        match result.unwrap_err() {
            PstError::SignerNotFound => {} // expected
            other => panic!("expected SignerNotFound, got: {other}"),
        }
    }

    #[test]
    fn pst_finalize_incomplete_errors() {
        let (tx, _sk, pk) = make_unsigned_tx();

        let (_, pk2_raw) = ed25519::generate_keypair();
        let pk2 = NoblePublicKey::Ed25519(pk2_raw);

        let mut pst = PartiallySignedTransaction::new(tx, None);
        pst.add_signer(pk, SignerRole::Primary);
        pst.add_signer(pk2, SignerRole::Additional);

        // Only unsigned — finalize should fail.
        assert!(!pst.is_complete());

        let result = pst.finalize();
        assert!(result.is_err());
        match result.unwrap_err() {
            PstError::Incomplete => {} // expected
            other => panic!("expected Incomplete, got: {other}"),
        }
    }
}
