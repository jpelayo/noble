// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE transaction type — Bitcoin-style UTXO model.
//!
//! Transactions consume UTXOs (inputs) and create new ones (outputs).
//! Fee = sum(input values) - sum(output values) — always implicit.
//! Coinbase transactions (TX_TYPE_COINBASE) carry block subsidy + collected fees.

use serde::{Deserialize, Serialize};

use noble_crypto::{double_sha256, sha256, Hash256, SignatureEnvelope};

use crate::encrypted_locator::{EncryptedLocator, ExternalAttestation};
use crate::metadata::MetadataEntry;
use crate::utxo::{TxIn, TxOut};

/// A NOBLE transaction: consumes UTXOs (inputs) and creates new ones (outputs).
///
/// Transaction types:
/// - `TX_TYPE_NOTARIZATION` (0x00): Document registration. Inputs pay the fee,
///   outputs return change. `checksum` carries the document hash.
/// - `TX_TYPE_TRANSFER` (0x01): Token transfer. Inputs are consumed, outputs
///   include recipient + change. Fee is implicit.
/// - `TX_TYPE_COINBASE` (0x10): Block reward. Single null input, outputs carry
///   subsidy + collected block fees. Always block index 0.
/// - `TX_TYPE_KEY_ROTATION` (0x02), badge types (0x03-0x05): Same UTXO pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Protocol version (must match PROTOCOL_VERSION).
    pub version: u16,
    /// Transaction type: 0x00=notarization, 0x01=transfer, 0x10=coinbase, etc.
    pub tx_type: u8,

    // ── UTXO fields ──

    /// Inputs: references to UTXOs being consumed.
    /// Coinbase has exactly one input with `OutPoint::COINBASE_PREVOUT`.
    pub inputs: Vec<TxIn>,
    /// Outputs: new UTXOs being created.
    pub outputs: Vec<TxOut>,

    // ── Retained fields ──

    /// SHA-256 checksum of the document being registered (notarizations).
    /// `Hash256::ZERO` for transfers and coinbase.
    pub checksum: Hash256,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Issuer's signature over the signing payload.
    pub issuer_sig: SignatureEnvelope,
    /// Additional co-signer signatures (accreditation bodies, labs, etc.).
    pub additional_sigs: Vec<SignatureEnvelope>,
    /// Key-value metadata entries.
    pub metadata: Vec<MetadataEntry>,
    /// Optional encrypted locator for private document sharing (notarization only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_locator: Option<EncryptedLocator>,
    /// Optional expiry timestamp (Unix seconds). If present, the transaction is invalid
    /// after this time. Enforced at both mempool admission and block validation.
    /// Clients set this to `timestamp + DEFAULT_TX_TTL_SECS` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// External attestations from non-NOBLE signature schemes (notarization only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_attestations: Vec<ExternalAttestation>,
    /// Gateway node address (wire bytes). If present, the gateway receives 50% of the fee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_address: Option<Vec<u8>>,
    /// Optional contract/script data (bytecode, parameters, or execution proof).
    /// Not subject to MAX_METADATA_VALUE_LEN — allows arbitrarily large payloads
    /// for contract deployment and invocation. Only valid for contract tx types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_data: Option<Vec<u8>>,
}

// NOTE: The old `SigningPayload` struct was removed — signing now uses
// `crate::wire::v1::tx_signing_payload_bytes()` directly.

impl Transaction {
    /// Compute the transaction ID: `double_sha256(chain_id_be || wire_bytes(tx))`.
    ///
    /// Uses the frozen wire format (no serde, no ciborium) for
    /// architecture-independent determinism.
    pub fn compute_tx_id(&self, chain_id: u32) -> Result<Hash256, noble_codec::CodecError> {
        use crate::wire::WireFormat;
        let tx_bytes = self.wire_bytes();
        let mut preimage = Vec::with_capacity(4 + tx_bytes.len());
        preimage.extend_from_slice(&chain_id.to_be_bytes());
        preimage.extend_from_slice(&tx_bytes);
        Ok(double_sha256(&preimage))
    }

    /// Compute the 32-byte signing message: `sha256(wire_bytes(signing_payload))`.
    ///
    /// Uses the frozen wire format for the signing payload. The payload commits
    /// to input outpoints, outputs, checksum, timestamp, metadata, and chain_id.
    /// Excludes issuer_sig and additional_sigs.
    pub fn compute_signing_message_for_chain(
        &self,
        chain_id: u32,
    ) -> Result<[u8; 32], noble_codec::CodecError> {
        let payload_bytes = crate::wire::v1::tx_signing_payload_bytes(self, chain_id);
        Ok(sha256(&payload_bytes).0)
    }

    /// Whether this is a coinbase transaction (block reward).
    pub fn is_coinbase(&self) -> bool {
        self.tx_type == crate::constants::TX_TYPE_COINBASE
            && self.inputs.len() == 1
            && self.inputs[0].prev_output.is_coinbase()
    }

    /// Sum of all output values (saturating — cannot overflow).
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().fold(0u64, |acc, o| acc.saturating_add(o.value))
    }

    /// Compute the implicit fee given the input UTXO values.
    ///
    /// Fee = sum(input_values) - sum(output_values).
    /// Returns `None` if inputs < outputs (invalid transaction).
    pub fn fee_from_inputs(&self, input_values: &[u64]) -> Option<u64> {
        let total_in: u64 = input_values.iter().copied().fold(0u64, |acc, v| acc.saturating_add(v));
        let total_out = self.total_output_value();
        total_in.checked_sub(total_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NobleAddress;
    use crate::constants::TX_TYPE_COINBASE;
    use crate::utxo::OutPoint;
    use noble_codec::NobleCbor;
    use noble_crypto::{secp256k1, NoblePrivateKey, NobleSigner, SCHEME_SECP256K1};

    fn make_test_keypair() -> (NoblePrivateKey, noble_crypto::NoblePublicKey) {
        let (sk, pk) = secp256k1::generate_keypair();
        (NoblePrivateKey::Secp256k1(sk), noble_crypto::NoblePublicKey::Secp256k1(pk))
    }

    /// Build a test notarization transaction (UTXO model).
    fn make_test_tx() -> Transaction {
        let (priv_key, pk) = make_test_keypair();
        let addr = NobleAddress::Noble(pk.clone());

        let input_outpoint = OutPoint {
            txid: Hash256::from_bytes([0x11; 32]),
            vout: 0,
        };

        let mut tx = Transaction {
            version: 1,
            tx_type: 0, // notarization
            inputs: vec![TxIn {
                prev_output: input_outpoint,
            }],
            outputs: vec![TxOut {
                value: 99_000, // change (input was 100_000, fee = 1_000)
                address: addr,
            }],
            checksum: Hash256::from_bytes([0xAB; 32]),
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.key_bytes().to_vec(),
                signature: vec![],
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
            expires_at: None,
        };

        let msg = tx.compute_signing_message_for_chain(0x4E4F424C).unwrap();
        let envelope = priv_key.sign(&msg).unwrap();
        tx.issuer_sig = envelope;
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
        let a = tx.compute_tx_id(0x4E4F424C).unwrap();
        let b = tx.compute_tx_id(0x5453544E).unwrap();
        assert_ne!(a, b, "tx_id must differ between chains");
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
    fn signing_message_changes_with_outputs() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        // Change the output value (different fee)
        tx.outputs[0].value = 50_000;
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_ne!(msg1, msg2, "signing message must change when outputs change");
    }

    #[test]
    fn signing_message_changes_with_inputs() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        // Change which UTXO is being spent
        tx.inputs[0].prev_output.vout = 99;
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_ne!(msg1, msg2, "signing message must change when inputs change");
    }

    #[test]
    fn signing_message_changes_with_version() {
        let mut tx = make_test_tx();
        let msg1 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        tx.version = 99;
        let msg2 = tx.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();
        assert_ne!(msg1, msg2);
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
            MetadataEntry { key: "z_key".into(), value: b"val".to_vec() },
            MetadataEntry { key: "a_key".into(), value: b"val".to_vec() },
        ];

        let mut tx2 = make_test_tx();
        tx2.metadata = vec![
            MetadataEntry { key: "a_key".into(), value: b"val".to_vec() },
            MetadataEntry { key: "z_key".into(), value: b"val".to_vec() },
        ];

        // Align non-metadata fields
        tx2.inputs = tx1.inputs.clone();
        tx2.outputs = tx1.outputs.clone();
        tx2.checksum = tx1.checksum;
        tx2.timestamp = tx1.timestamp;

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
    fn cbor_roundtrip_via_codec() {
        let tx = make_test_tx();
        let bytes = tx.to_cbor().unwrap();
        let decoded = Transaction::from_cbor(&bytes).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn signing_payload_includes_gateway_address() {
        let tx_none = make_test_tx();
        let msg_none = tx_none.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();

        let mut tx_gw = make_test_tx();
        tx_gw.inputs = tx_none.inputs.clone();
        tx_gw.outputs = tx_none.outputs.clone();
        tx_gw.checksum = tx_none.checksum;
        tx_gw.timestamp = tx_none.timestamp;
        tx_gw.gateway_address = Some(vec![0x01; 33]);
        let msg_gw = tx_gw.compute_signing_message_for_chain(TEST_CHAIN_ID).unwrap();

        assert_ne!(msg_none, msg_gw, "signing message must change with gateway_address");
    }

    #[test]
    fn signing_message_differs_by_chain_id() {
        let tx = make_test_tx();
        let a = tx.compute_signing_message_for_chain(0x4E4F424C).unwrap();
        let b = tx.compute_signing_message_for_chain(0x5453544E).unwrap();
        assert_ne!(a, b, "signing message must differ between chains");
    }

    #[test]
    fn is_coinbase_detection() {
        let (_, pk) = make_test_keypair();
        let addr = NobleAddress::Noble(pk.clone());

        let coinbase = Transaction {
            version: 1,
            tx_type: TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value: 100_000_000, address: addr.clone() }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1, public_key: pk.key_bytes().to_vec(), signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        assert!(coinbase.is_coinbase());

        let regular = make_test_tx();
        assert!(!regular.is_coinbase());
    }

    #[test]
    fn total_output_value() {
        let (_, pk) = make_test_keypair();
        let addr = NobleAddress::Noble(pk.clone());

        let tx = Transaction {
            version: 1,
            tx_type: 1,
            inputs: vec![],
            outputs: vec![
                TxOut { value: 50_000, address: addr.clone() },
                TxOut { value: 30_000, address: addr },
            ],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1, public_key: pk.key_bytes().to_vec(), signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        assert_eq!(tx.total_output_value(), 80_000);
    }

    #[test]
    fn fee_from_inputs_correct() {
        let tx = make_test_tx();
        // Test tx has output value 99_000. If input was 100_000, fee = 1_000.
        let fee = tx.fee_from_inputs(&[100_000]);
        assert_eq!(fee, Some(1_000));
    }

    #[test]
    fn fee_from_inputs_insufficient() {
        let tx = make_test_tx();
        // Output is 99_000 but input only 50_000 — insufficient
        let fee = tx.fee_from_inputs(&[50_000]);
        assert_eq!(fee, None);
    }

    #[test]
    fn fee_from_inputs_exact() {
        let tx = make_test_tx();
        // Input exactly equals output — fee = 0
        let fee = tx.fee_from_inputs(&[99_000]);
        assert_eq!(fee, Some(0));
    }
}
