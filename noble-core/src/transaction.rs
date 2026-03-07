// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE transaction type — notarization claims and token transfers.

use serde::{Deserialize, Serialize};

use noble_codec::NobleCbor;
use noble_crypto::{double_sha256, sha256, Hash256, SignatureEnvelope};

use crate::address::NobleAddress;

use crate::encrypted_locator::{EncryptedLocator, ExternalAttestation};
use crate::metadata::MetadataEntry;

/// A NOBLE transaction: either a notarization claim binding a document checksum
/// to a publisher identity, or a token transfer between addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Protocol version (must match PROTOCOL_VERSION).
    pub version: u16,
    /// Transaction type: 0x00 = notarization, 0x01 = transfer (GAP-M26).
    pub tx_type: u8,
    /// SHA-256 checksum of the document being registered.
    pub checksum: Hash256,
    /// Unix timestamp (seconds) of the registration claim.
    pub timestamp: u64,
    /// Fee in atomic units (GAP-C2).
    pub fee: u64,
    /// Recipient address (present for transfers only).
    /// Accepts both native NOBLE public keys and Bitcoin-format addresses.
    pub recipient: Option<NobleAddress>,
    /// Transfer amount in atomic units (present for transfers only).
    pub amount: Option<u64>,
    /// Publisher's signature over the signing payload.
    pub publisher_sig: SignatureEnvelope,
    /// Additional co-signer signatures (accreditation bodies, labs, etc.).
    pub additional_sigs: Vec<SignatureEnvelope>,
    /// Key-value metadata entries.
    pub metadata: Vec<MetadataEntry>,
    /// Optional encrypted locator for private document sharing (notarization only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_locator: Option<EncryptedLocator>,
    /// External attestations from non-NOBLE signature schemes (notarization only).
    /// Protocol-opaque: stored but never validated by the node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_attestations: Vec<ExternalAttestation>,
    /// Gateway node address (wire bytes). If present, the gateway receives 50% of the fee.
    /// Set by the node's RPC handler when it first accepts the transaction from the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<Vec<u8>>,
    /// Explicit source (debit) address for transfers (S34).
    /// Wire-encoded `NobleAddress` bytes indicating which balance bucket to debit.
    /// When absent, legacy fallback applies (Noble first, Hash160 for secp256k1).
    /// Required for secp256k1 senders at/above SOURCE_ADDRESS_ACTIVATION_HEIGHT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<Vec<u8>>,
}

/// Internal struct used to compute the signing message (GAP-C1).
///
/// The signing payload is a CBOR-structured message containing only the
/// fields that the signer commits to. The publisher signature and additional
/// signatures are NOT included (they're the things being produced/verified).
///
/// Fields: `version`, `tx_type`, `checksum`, `timestamp`, `fee`,
/// `recipient` (optional), `amount` (optional), `metadata` (sorted by key),
/// `encrypted_locator` (optional), `external_attestations` (optional).
#[derive(Serialize)]
struct SigningPayload {
    version: u16,
    tx_type: u8,
    checksum: Hash256,
    timestamp: u64,
    fee: u64,
    recipient: Option<NobleAddress>,
    amount: Option<u64>,
    metadata: Vec<MetadataEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_locator: Option<EncryptedLocator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_attestations: Vec<ExternalAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_address: Option<Vec<u8>>,
    /// S34: Source address commits the debit bucket into the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_address: Option<Vec<u8>>,
    /// AUD2-H7: Chain identifier prevents cross-chain signature replay.
    /// Default 0 = legacy (pre-Sprint 9) compatibility.
    #[serde(default)]
    chain_id: u32,
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
    /// The chain_id prevents cross-chain signature replay.
    pub fn compute_signing_message_for_chain(
        &self,
        chain_id: u32,
    ) -> Result<[u8; 32], noble_codec::CodecError> {
        let mut sorted_metadata = self.metadata.clone();
        sorted_metadata.sort_by(|a, b| a.key.cmp(&b.key));

        let payload = SigningPayload {
            version: self.version,
            tx_type: self.tx_type,
            checksum: self.checksum,
            timestamp: self.timestamp,
            fee: self.fee,
            recipient: self.recipient.clone(),
            amount: self.amount,
            metadata: sorted_metadata,
            encrypted_locator: self.encrypted_locator.clone(),
            external_attestations: self.external_attestations.clone(),
            gateway_address: self.gateway_address.clone(),
            source_address: self.source_address.clone(),
            chain_id,
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
            tx_type: 0,
            checksum,
            timestamp,
            fee,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk,
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
        };

        // Sign with the actual signing message (use a test chain_id)
        let msg = tx.compute_signing_message_for_chain(0x4E4F424C).unwrap();
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
        let chain_a_id = tx.compute_tx_id(0x4E4F424C).unwrap();
        let chain_b_id = tx.compute_tx_id(0x5453544E).unwrap();
        assert_ne!(
            chain_a_id, chain_b_id,
            "tx_id must differ between chains (GAP-H2)"
        );
    }

    const TEST_CHAIN_ID: u32 = 0x4E4F424C;

    #[test]
    fn signing_message_deterministic() {
        let tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn signing_message_is_32_bytes() {
        let tx = make_test_tx();
        let msg = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn signing_message_changes_with_fee() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        tx.fee = 2_000;
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_ne!(msg1, msg2, "signing message must change when fee changes");
    }

    #[test]
    fn signing_message_changes_with_version() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        tx.version = 99;
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_ne!(
            msg1, msg2,
            "signing message must change when version changes"
        );
    }

    #[test]
    fn signing_message_changes_with_checksum() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        tx.checksum = Hash256::from_bytes([0xCD; 32]);
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
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

        tx2.checksum = tx1.checksum;
        tx2.timestamp = tx1.timestamp;
        tx2.fee = tx1.fee;
        let msg1 = tx1.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        let msg2 = tx2.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
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

    #[test]
    fn signing_payload_includes_gateway_address() {
        let tx_none = make_test_tx();
        let msg_none = tx_none.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();

        let mut tx_gw = make_test_tx();
        tx_gw.checksum = tx_none.checksum;
        tx_gw.timestamp = tx_none.timestamp;
        tx_gw.fee = tx_none.fee;
        tx_gw.gateway_address = Some(vec![0x01; 33]);
        let msg_gw = tx_gw.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();

        assert_ne!(
            msg_none, msg_gw,
            "signing message must change when gateway_address is set"
        );
    }

    #[test]
    fn signing_message_differs_by_chain_id() {
        let tx = make_test_tx();
        let chain_a_msg = tx
            .compute_signing_message_for_chain(0x4E4F424C)
            .unwrap();
        let chain_b_msg = tx
            .compute_signing_message_for_chain(0x5453544E)
            .unwrap();
        assert_ne!(
            chain_a_msg, chain_b_msg,
            "signing message must differ between chains (AUD2-H7)"
        );
    }

    #[test]
    fn tx_without_gateway_backward_compat_cbor() {
        let tx = make_test_tx();
        assert!(tx.gateway_address.is_none());

        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        assert_eq!(tx, decoded);
        assert!(decoded.gateway_address.is_none());
    }
}
