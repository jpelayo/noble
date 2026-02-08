// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE transaction type — a notarization claim for document checksums.

use serde::{Deserialize, Serialize};

use noble_codec::NobleCbor;
use noble_crypto::{double_sha256, sha256, Hash256, SignatureEnvelope};

use crate::metadata::MetadataEntry;

/// A NOBLE transaction: a notarization claim binding a document checksum
/// to a publisher identity at a specific time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Protocol version (must match PROTOCOL_VERSION).
    pub version: u16,
    /// SHA-256 checksum of the document being registered.
    pub checksum: Hash256,
    /// Unix timestamp (seconds) of the registration claim.
    pub timestamp: u64,
    /// Fee in atomic units (GAP-C2).
    pub fee: u64,
    /// Publisher's signature over the signing payload.
    pub publisher_sig: SignatureEnvelope,
    /// Additional co-signer signatures (accreditation bodies, labs, etc.).
    pub additional_sigs: Vec<SignatureEnvelope>,
    /// Key-value metadata entries.
    pub metadata: Vec<MetadataEntry>,
}

/// Internal struct used to compute the signing message (GAP-C1).
///
/// The signing payload is a CBOR-structured message containing only the
/// fields that the signer commits to. The publisher signature and additional
/// signatures are NOT included (they're the things being produced/verified).
#[derive(Serialize)]
struct SigningPayload {
    checksum: Hash256,
    timestamp: u64,
    fee: u64,
    metadata: Vec<MetadataEntry>,
}

impl Transaction {
    /// Compute the transaction ID: `double_sha256(chain_id_be || canonical_cbor(tx))` (GAP-H2).
    ///
    /// The chain_id is prepended to prevent cross-chain replay attacks.
    pub fn compute_tx_id(&self, chain_id: u32) -> Result<Hash256, noble_codec::CodecError> {
        let tx_bytes = self.canonical_bytes()?;
        let mut preimage = Vec::with_capacity(4 + tx_bytes.len());
        preimage.extend_from_slice(&chain_id.to_be_bytes());
        preimage.extend_from_slice(&tx_bytes);
        Ok(double_sha256(&preimage))
    }

    /// Compute the 32-byte signing message: `sha256(canonical_cbor(SigningPayload))` (GAP-C1).
    ///
    /// The signing payload includes checksum, timestamp, fee, and sorted metadata.
    /// Fee is included for atomic commitment (no tx malleability).
    pub fn compute_signing_message(&self) -> Result<[u8; 32], noble_codec::CodecError> {
        let mut sorted_metadata = self.metadata.clone();
        sorted_metadata.sort_by(|a, b| a.key.cmp(&b.key));

        let payload = SigningPayload {
            checksum: self.checksum,
            timestamp: self.timestamp,
            fee: self.fee,
            metadata: sorted_metadata,
        };

        let canonical = noble_codec::to_canonical_cbor(&payload)?;
        Ok(sha256(&canonical).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{ed25519, NoblePrivateKey, NobleSigner, SCHEME_ED25519};

    fn make_test_tx() -> Transaction {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);

        let checksum = Hash256::from_bytes([0xAB; 32]);
        let timestamp = 1_700_000_000u64;
        let fee = 1_000u64;
        let metadata = vec![MetadataEntry {
            key: "doc_type".into(),
            value: b"test_report".to_vec(),
        }];

        // Build a minimal transaction to get the signing message
        let mut tx = Transaction {
            version: 1,
            checksum,
            timestamp,
            fee,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk,
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
        };

        // Sign with the actual signing message
        let msg = tx.compute_signing_message().unwrap();
        let envelope = priv_key.sign(&msg).unwrap();
        tx.publisher_sig = envelope;
        tx
    }

    #[test]
    fn tx_id_deterministic() {
        let tx = make_test_tx();
        let id1 = tx.compute_tx_id(0x4E4F424C).unwrap();
        let id2 = tx.compute_tx_id(0x4E4F424C).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_id_differs_by_chain_id() {
        let tx = make_test_tx();
        let mainnet_id = tx.compute_tx_id(0x4E4F424C).unwrap();
        let testnet_id = tx.compute_tx_id(0x5453544E).unwrap();
        assert_ne!(
            mainnet_id, testnet_id,
            "tx_id must differ between chains (GAP-H2)"
        );
    }

    #[test]
    fn signing_message_deterministic() {
        let tx = make_test_tx();
        let msg1 = tx.compute_signing_message().unwrap();
        let msg2 = tx.compute_signing_message().unwrap();
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn signing_message_is_32_bytes() {
        let tx = make_test_tx();
        let msg = tx.compute_signing_message().unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn signing_message_changes_with_fee() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message().unwrap();
        tx.fee = 2_000;
        let msg2 = tx.compute_signing_message().unwrap();
        assert_ne!(msg1, msg2, "signing message must change when fee changes");
    }

    #[test]
    fn signing_message_changes_with_checksum() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message().unwrap();
        tx.checksum = Hash256::from_bytes([0xCD; 32]);
        let msg2 = tx.compute_signing_message().unwrap();
        assert_ne!(msg1, msg2);
    }

    #[test]
    fn signing_message_metadata_order_independent() {
        let mut tx1 = make_test_tx();
        tx1.metadata = vec![
            MetadataEntry {
                key: "z_key".into(),
                value: b"val".to_vec(),
            },
            MetadataEntry {
                key: "a_key".into(),
                value: b"val".to_vec(),
            },
        ];

        let mut tx2 = make_test_tx();
        tx2.metadata = vec![
            MetadataEntry {
                key: "a_key".into(),
                value: b"val".to_vec(),
            },
            MetadataEntry {
                key: "z_key".into(),
                value: b"val".to_vec(),
            },
        ];

        // Both should produce the same signing message (metadata is pre-sorted)
        tx2.checksum = tx1.checksum;
        tx2.timestamp = tx1.timestamp;
        tx2.fee = tx1.fee;
        let msg1 = tx1.compute_signing_message().unwrap();
        let msg2 = tx2.compute_signing_message().unwrap();
        assert_eq!(msg1, msg2, "metadata order must not affect signing message");
    }

    #[test]
    fn cbor_roundtrip() {
        let tx = make_test_tx();
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn canonical_roundtrip() {
        let tx = make_test_tx();
        let canonical = tx.canonical_bytes().unwrap();
        let decoded = Transaction::from_cbor(&canonical).unwrap();
        assert_eq!(tx, decoded);
    }
}
