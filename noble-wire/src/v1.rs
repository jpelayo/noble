// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Wire Format V1 implementations for all types in the hashing critical path.
//!
//! FROZEN: These implementations define the byte-level encoding used to
//! compute block hashes, transaction IDs, and signing messages. Any change
//! to the encoding of a type breaks all existing hashes that include it.
//!
//! # Canonical Map Key Order
//!
//! All struct fields are encoded as CBOR map entries with text string keys,
//! sorted alphabetically (RFC 8949 deterministic encoding). The sort order
//! is by raw UTF-8 bytes, which for ASCII field names is the same as
//! lexicographic string order.

use crate::cbor;
use crate::WireFormat;
use noble_core::address::NobleAddress;
use noble_core::block::BlockHeader;
use noble_core::encrypted_locator::{EncryptedLocator, ExternalAttestation, LocatorRecipient};
use noble_core::metadata::MetadataEntry;
use noble_core::transaction::Transaction;
use noble_core::utxo::{OutPoint, TxIn, TxOut};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};

// ── Leaf types ──────────────────────────────────────────────────────────

impl WireFormat for Hash256 {
    /// CBOR byte string (major type 2), 32 bytes.
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        cbor::write_bytes(buf, self.as_bytes());
    }
}

impl WireFormat for NoblePublicKey {
    /// CBOR byte string: `[scheme_id(1) || key_bytes(32 or 33)]`.
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        let wire = self.to_wire_bytes();
        cbor::write_bytes(buf, &wire);
    }
}

impl WireFormat for NobleAddress {
    /// CBOR byte string: `[prefix(1) || address_data]`.
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        let wire = self.to_wire_bytes();
        cbor::write_bytes(buf, &wire);
    }
}

impl WireFormat for SignatureEnvelope {
    /// CBOR byte string: `[scheme_id(1) || pubkey_len(1) || pubkey || sig]`.
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        let pk_len = self.public_key.len();
        debug_assert!(pk_len <= 255, "public key exceeds u8 length encoding ({pk_len} bytes)");
        let total = 1 + 1 + pk_len + self.signature.len();
        let mut wire = Vec::with_capacity(total);
        wire.push(self.scheme_id);
        wire.push(pk_len.min(255) as u8);
        wire.extend_from_slice(&self.public_key);
        wire.extend_from_slice(&self.signature);
        cbor::write_bytes(buf, &wire);
    }
}

impl WireFormat for MetadataEntry {
    /// CBOR map(2): { "key": text, "value": bytes }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "key" < "value"
        cbor::write_map(buf, 2);
        cbor::write_text(buf, "key");
        cbor::write_text(buf, &self.key);
        cbor::write_text(buf, "value");
        cbor::write_bytes(buf, &self.value);
    }
}

// ── UTXO types ──────────────────────────────────────────────────────────

impl WireFormat for OutPoint {
    /// CBOR map(2): { "txid": bytes, "vout": uint }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "txid" < "vout"
        cbor::write_map(buf, 2);
        cbor::write_text(buf, "txid");
        self.txid.encode_wire(buf);
        cbor::write_text(buf, "vout");
        cbor::write_uint(buf, self.vout as u64);
    }
}

impl WireFormat for TxIn {
    /// CBOR map(1): { "prev_output": OutPoint }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        cbor::write_map(buf, 1);
        cbor::write_text(buf, "prev_output");
        self.prev_output.encode_wire(buf);
    }
}

impl WireFormat for TxOut {
    /// CBOR map(2): { "address": NobleAddress, "value": uint }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "address" < "value"
        cbor::write_map(buf, 2);
        cbor::write_text(buf, "address");
        self.address.encode_wire(buf);
        cbor::write_text(buf, "value");
        cbor::write_uint(buf, self.value);
    }
}

// ── Encrypted locator types ─────────────────────────────────────────────

impl WireFormat for LocatorRecipient {
    /// CBOR map(4): { "encrypted_key", "ephemeral_pubkey", "key_nonce", "recipient" }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "encrypted_key" < "ephemeral_pubkey" < "key_nonce" < "recipient"
        cbor::write_map(buf, 4);
        cbor::write_text(buf, "encrypted_key");
        cbor::write_bytes(buf, &self.encrypted_key);
        cbor::write_text(buf, "ephemeral_pubkey");
        cbor::write_bytes(buf, &self.ephemeral_pubkey);
        cbor::write_text(buf, "key_nonce");
        cbor::write_bytes(buf, &self.key_nonce);
        cbor::write_text(buf, "recipient");
        self.recipient.encode_wire(buf);
    }
}

impl WireFormat for EncryptedLocator {
    /// CBOR map(3): { "ciphertext", "nonce", "recipients" }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "ciphertext" < "nonce" < "recipients"
        cbor::write_map(buf, 3);
        cbor::write_text(buf, "ciphertext");
        cbor::write_bytes(buf, &self.ciphertext);
        cbor::write_text(buf, "nonce");
        cbor::write_bytes(buf, &self.nonce);
        cbor::write_text(buf, "recipients");
        cbor::write_array(buf, self.recipients.len());
        for r in &self.recipients {
            r.encode_wire(buf);
        }
    }
}

impl WireFormat for ExternalAttestation {
    /// CBOR map(4): { "scheme", "scope", "signature_data", "signer_fingerprint" }
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        // Sorted keys: "scheme" < "scope" < "signature_data" < "signer_fingerprint"
        cbor::write_map(buf, 4);
        cbor::write_text(buf, "scheme");
        cbor::write_text(buf, &self.scheme);
        cbor::write_text(buf, "scope");
        cbor::write_text(buf, &self.scope);
        cbor::write_text(buf, "signature_data");
        cbor::write_bytes(buf, &self.signature_data);
        cbor::write_text(buf, "signer_fingerprint");
        cbor::write_bytes(buf, &self.signer_fingerprint);
    }
}

// ── Transaction ─────────────────────────────────────────────────────────

impl WireFormat for Transaction {
    /// CBOR map with 9-12 entries (depending on optional fields).
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        let mut field_count: usize = 9;
        if self.encrypted_locator.is_some() { field_count += 1; }
        if !self.external_attestations.is_empty() { field_count += 1; }
        if self.gateway_address.is_some() { field_count += 1; }

        cbor::write_map(buf, field_count);

        // "additional_sigs"
        cbor::write_text(buf, "additional_sigs");
        cbor::write_array(buf, self.additional_sigs.len());
        for sig in &self.additional_sigs { sig.encode_wire(buf); }

        // "checksum"
        cbor::write_text(buf, "checksum");
        self.checksum.encode_wire(buf);

        // "encrypted_locator" — omitted when None
        if let Some(ref loc) = self.encrypted_locator {
            cbor::write_text(buf, "encrypted_locator");
            loc.encode_wire(buf);
        }

        // "external_attestations" — omitted when empty
        if !self.external_attestations.is_empty() {
            cbor::write_text(buf, "external_attestations");
            cbor::write_array(buf, self.external_attestations.len());
            for att in &self.external_attestations { att.encode_wire(buf); }
        }

        // "gateway_address" — omitted when None
        if let Some(ref addr) = self.gateway_address {
            cbor::write_text(buf, "gateway_address");
            cbor::write_bytes(buf, addr);
        }

        // "inputs"
        cbor::write_text(buf, "inputs");
        cbor::write_array(buf, self.inputs.len());
        for inp in &self.inputs { inp.encode_wire(buf); }

        // "metadata"
        cbor::write_text(buf, "metadata");
        cbor::write_array(buf, self.metadata.len());
        for m in &self.metadata { m.encode_wire(buf); }

        // "outputs"
        cbor::write_text(buf, "outputs");
        cbor::write_array(buf, self.outputs.len());
        for out in &self.outputs { out.encode_wire(buf); }

        // "publisher_sig"
        cbor::write_text(buf, "publisher_sig");
        self.publisher_sig.encode_wire(buf);

        // "timestamp"
        cbor::write_text(buf, "timestamp");
        cbor::write_uint(buf, self.timestamp);

        // "tx_type"
        cbor::write_text(buf, "tx_type");
        cbor::write_uint(buf, self.tx_type as u64);

        // "version"
        cbor::write_text(buf, "version");
        cbor::write_uint(buf, self.version as u64);
    }
}

// ── BlockHeader ─────────────────────────────────────────────────────────

impl WireFormat for BlockHeader {
    /// CBOR map(8): all fields always present.
    fn encode_wire(&self, buf: &mut Vec<u8>) {
        cbor::write_map(buf, 8);

        cbor::write_text(buf, "height");
        cbor::write_uint(buf, self.height);

        cbor::write_text(buf, "merkle_root");
        self.merkle_root.encode_wire(buf);

        cbor::write_text(buf, "prev_block_hash");
        self.prev_block_hash.encode_wire(buf);

        cbor::write_text(buf, "timestamp");
        cbor::write_uint(buf, self.timestamp);

        cbor::write_text(buf, "tx_count");
        cbor::write_uint(buf, self.tx_count as u64);

        cbor::write_text(buf, "validator_id");
        self.validator_id.encode_wire(buf);

        cbor::write_text(buf, "validator_sig");
        self.validator_sig.encode_wire(buf);

        cbor::write_text(buf, "version");
        cbor::write_uint(buf, self.version as u64);
    }
}

// ── Signing Payloads ────────────────────────────────────────────────────

/// Encode a transaction signing payload to frozen wire bytes.
pub fn tx_signing_payload_bytes(tx: &Transaction, chain_id: u32) -> Vec<u8> {
    let mut field_count: usize = 8;
    if tx.encrypted_locator.is_some() { field_count += 1; }
    if !tx.external_attestations.is_empty() { field_count += 1; }
    if tx.gateway_address.is_some() { field_count += 1; }

    let mut buf = Vec::with_capacity(256);
    cbor::write_map(&mut buf, field_count);

    cbor::write_text(&mut buf, "chain_id");
    cbor::write_uint(&mut buf, chain_id as u64);

    cbor::write_text(&mut buf, "checksum");
    tx.checksum.encode_wire(&mut buf);

    if let Some(ref loc) = tx.encrypted_locator {
        cbor::write_text(&mut buf, "encrypted_locator");
        loc.encode_wire(&mut buf);
    }

    if !tx.external_attestations.is_empty() {
        cbor::write_text(&mut buf, "external_attestations");
        cbor::write_array(&mut buf, tx.external_attestations.len());
        for att in &tx.external_attestations { att.encode_wire(&mut buf); }
    }

    if let Some(ref addr) = tx.gateway_address {
        cbor::write_text(&mut buf, "gateway_address");
        cbor::write_bytes(&mut buf, addr);
    }

    cbor::write_text(&mut buf, "input_outpoints");
    cbor::write_array(&mut buf, tx.inputs.len());
    for inp in &tx.inputs { inp.prev_output.encode_wire(&mut buf); }

    cbor::write_text(&mut buf, "metadata");
    cbor::write_array(&mut buf, tx.metadata.len());
    for m in &tx.metadata { m.encode_wire(&mut buf); }

    cbor::write_text(&mut buf, "outputs");
    cbor::write_array(&mut buf, tx.outputs.len());
    for out in &tx.outputs { out.encode_wire(&mut buf); }

    cbor::write_text(&mut buf, "timestamp");
    cbor::write_uint(&mut buf, tx.timestamp);

    cbor::write_text(&mut buf, "tx_type");
    cbor::write_uint(&mut buf, tx.tx_type as u64);

    cbor::write_text(&mut buf, "version");
    cbor::write_uint(&mut buf, tx.version as u64);

    buf
}

/// Encode a block header signing payload to frozen wire bytes.
pub fn header_signing_payload_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    cbor::write_map(&mut buf, 7);

    cbor::write_text(&mut buf, "height");
    cbor::write_uint(&mut buf, header.height);

    cbor::write_text(&mut buf, "merkle_root");
    header.merkle_root.encode_wire(&mut buf);

    cbor::write_text(&mut buf, "prev_block_hash");
    header.prev_block_hash.encode_wire(&mut buf);

    cbor::write_text(&mut buf, "timestamp");
    cbor::write_uint(&mut buf, header.timestamp);

    cbor::write_text(&mut buf, "tx_count");
    cbor::write_uint(&mut buf, header.tx_count as u64);

    cbor::write_text(&mut buf, "validator_id");
    header.validator_id.encode_wire(&mut buf);

    cbor::write_text(&mut buf, "version");
    cbor::write_uint(&mut buf, header.version as u64);

    buf
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::utxo::OutPoint;
    use noble_crypto::{Hash256, SCHEME_ED25519};

    #[test]
    fn hash256_wire_bytes() {
        let h = Hash256::ZERO;
        let bytes = h.wire_bytes();
        assert_eq!(bytes.len(), 34);
        assert_eq!(bytes[0], 0x58);
        assert_eq!(bytes[1], 0x20);
        assert_eq!(&bytes[2..], &[0u8; 32]);
    }

    #[test]
    fn noble_public_key_wire_bytes() {
        let pk = NoblePublicKey::Ed25519(vec![0xAA; 32]);
        let bytes = pk.wire_bytes();
        assert_eq!(bytes[0], 0x58);
        assert_eq!(bytes[1], 33);
        assert_eq!(bytes[2], SCHEME_ED25519);
        assert_eq!(&bytes[3..], &[0xAA; 32]);
    }

    #[test]
    fn signature_envelope_wire_bytes() {
        let sig = SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: vec![0xBB; 32],
            signature: vec![0xCC; 64],
        };
        let bytes = sig.wire_bytes();
        assert_eq!(bytes[0], 0x58);
        assert_eq!(bytes[1], 98);
        assert_eq!(bytes[2], SCHEME_ED25519);
        assert_eq!(bytes[3], 32);
        assert_eq!(&bytes[4..36], &[0xBB; 32]);
        assert_eq!(&bytes[36..100], &[0xCC; 64]);
    }

    #[test]
    fn outpoint_wire_bytes() {
        let op = OutPoint::COINBASE_PREVOUT;
        let bytes = op.wire_bytes();
        assert_eq!(bytes[0], 0xA2);
        assert_eq!(bytes[1], 0x64);
        assert_eq!(&bytes[2..6], b"txid");
        assert_eq!(bytes[6], 0x58);
        assert_eq!(bytes[7], 0x20);
        assert_eq!(bytes[40], 0x64);
        assert_eq!(&bytes[41..45], b"vout");
        assert_eq!(bytes[45], 0x1A);
    }

    #[test]
    fn metadata_entry_wire_bytes() {
        let m = MetadataEntry {
            key: "doc_type".to_string(),
            value: b"certificate".to_vec(),
        };
        let bytes = m.wire_bytes();
        assert_eq!(bytes[0], 0xA2);
        assert_eq!(bytes[1], 0x63);
        assert_eq!(&bytes[2..5], b"key");
    }

    #[test]
    fn wire_bytes_deterministic() {
        let pk = NoblePublicKey::Ed25519(vec![0x42; 32]);
        assert_eq!(pk.wire_bytes(), pk.wire_bytes());

        let op = OutPoint { txid: Hash256::from_bytes([0xAB; 32]), vout: 42 };
        assert_eq!(op.wire_bytes(), op.wire_bytes());
    }

    #[test]
    fn encode_wire_matches_wire_bytes() {
        // Verify the default wire_bytes() wrapper matches direct encode_wire
        let pk = NoblePublicKey::Ed25519(vec![0x42; 32]);
        let mut direct = Vec::new();
        pk.encode_wire(&mut direct);
        assert_eq!(direct, pk.wire_bytes());
    }

    #[test]
    fn transaction_wire_bytes_field_count() {
        let coinbase = Transaction {
            version: 1,
            tx_type: 0x10,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut {
                value: 100_000_000,
                address: NobleAddress::Noble(NoblePublicKey::Ed25519(vec![0x42; 32])),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: vec![0x42; 32],
                signature: vec![0x00; 64],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        };
        let bytes = coinbase.wire_bytes();
        assert_eq!(bytes[0], 0xA9); // map, 9 pairs
    }

    #[test]
    fn block_header_wire_bytes() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_bytes([0xFF; 32]),
            timestamp: 1_700_000_000,
            height: 42,
            tx_count: 1,
            validator_id: NoblePublicKey::Ed25519(vec![0x42; 32]),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: vec![0x42; 32],
                signature: vec![0x00; 64],
            },
        };
        let bytes = header.wire_bytes();
        assert_eq!(bytes[0], 0xA8);
        assert_eq!(bytes[1], 0x66);
        assert_eq!(&bytes[2..8], b"height");
    }
}
