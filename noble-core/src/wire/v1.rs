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
//! sorted alphabetically by field name (ASCII lexicographic). This is NOT
//! the same as RFC 8949 Section 4.2.1 (which sorts by encoded byte length
//! first). The alphabetical ordering is simpler, deterministic, and frozen
//! as part of Wire Format V1.

use super::cbor;
use super::WireFormat;
use crate::address::NobleAddress;
use crate::block::BlockHeader;
use crate::encrypted_locator::{EncryptedLocator, ExternalAttestation, LocatorRecipient};
use crate::metadata::MetadataEntry;
use crate::transaction::Transaction;
use crate::utxo::{OutPoint, TxIn, TxOut};
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
        if self.contract_data.is_some() { field_count += 1; }
        if self.encrypted_locator.is_some() { field_count += 1; }
        if self.expires_at.is_some() { field_count += 1; }
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

        // "contract_data" — omitted when None
        if let Some(ref data) = self.contract_data {
            cbor::write_text(buf, "contract_data");
            cbor::write_bytes(buf, data);
        }

        // "encrypted_locator" — omitted when None
        if let Some(ref loc) = self.encrypted_locator {
            cbor::write_text(buf, "encrypted_locator");
            loc.encode_wire(buf);
        }

        // "expires_at" — omitted when None
        if let Some(exp) = self.expires_at {
            cbor::write_text(buf, "expires_at");
            cbor::write_uint(buf, exp);
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

        // "issuer_sig" (alphabetically between "inputs" and "metadata")
        cbor::write_text(buf, "issuer_sig");
        self.issuer_sig.encode_wire(buf);

        // "metadata"
        cbor::write_text(buf, "metadata");
        cbor::write_array(buf, self.metadata.len());
        for m in &self.metadata { m.encode_wire(buf); }

        // "outputs"
        cbor::write_text(buf, "outputs");
        cbor::write_array(buf, self.outputs.len());
        for out in &self.outputs { out.encode_wire(buf); }

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
    if tx.contract_data.is_some() { field_count += 1; }
    if tx.encrypted_locator.is_some() { field_count += 1; }
    if tx.expires_at.is_some() { field_count += 1; }
    if !tx.external_attestations.is_empty() { field_count += 1; }
    if tx.gateway_address.is_some() { field_count += 1; }

    let mut buf = Vec::with_capacity(256);
    cbor::write_map(&mut buf, field_count);

    cbor::write_text(&mut buf, "chain_id");
    cbor::write_uint(&mut buf, chain_id as u64);

    cbor::write_text(&mut buf, "checksum");
    tx.checksum.encode_wire(&mut buf);

    if let Some(ref data) = tx.contract_data {
        cbor::write_text(&mut buf, "contract_data");
        cbor::write_bytes(&mut buf, data);
    }

    if let Some(ref loc) = tx.encrypted_locator {
        cbor::write_text(&mut buf, "encrypted_locator");
        loc.encode_wire(&mut buf);
    }

    if let Some(exp) = tx.expires_at {
        cbor::write_text(&mut buf, "expires_at");
        cbor::write_uint(&mut buf, exp);
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

    // Sort metadata by key for order-independent signing.
    let mut sorted_metadata: Vec<&crate::metadata::MetadataEntry> = tx.metadata.iter().collect();
    sorted_metadata.sort_by(|a, b| a.key.cmp(&b.key));

    cbor::write_text(&mut buf, "metadata");
    cbor::write_array(&mut buf, sorted_metadata.len());
    for m in &sorted_metadata { m.encode_wire(&mut buf); }

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

// ── Vote Signing Payload ─────────────────────────────────────────────────

/// Encode a vote signing payload to frozen wire bytes.
///
/// Fields (3): candidate_hash, cycle, round — sorted alphabetically.
pub fn vote_signing_payload_bytes(cycle: u64, candidate_hash: &Hash256, round: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48);
    cbor::write_map(&mut buf, 3);

    cbor::write_text(&mut buf, "candidate_hash");
    candidate_hash.encode_wire(&mut buf);

    cbor::write_text(&mut buf, "cycle");
    cbor::write_uint(&mut buf, cycle);

    cbor::write_text(&mut buf, "round");
    cbor::write_uint(&mut buf, round as u64);

    buf
}

// ── NodeAnnounce Signing Payload ────────────────────────────────────────

/// Encode a NodeAnnounce signing payload to frozen wire bytes.
///
/// Includes all announce fields EXCEPT signature and identity_attestation.
/// Uses the node_announce module types directly.
pub fn announce_signing_payload_bytes(announce: &crate::node_announce::NodeAnnounce) -> Vec<u8> {

    // Count present fields. Base: 15 always-present fields:
    // chain_id, contact_email, host_address, identity_key, network_name,
    // node_name, node_role, org_name, org_type, software_version,
    // timestamp, version, wants_to_validate, wants_to_vote, website.
    // Conditional (6): chain_tip_hash, chain_tip_height, chain_vote_weight,
    // country_code, proposed_hash, proposed_height.
    let mut field_count: usize = 15;
    if announce.country_code.is_some() { field_count += 1; }
    if announce.chain_tip_height.is_some() { field_count += 1; }
    if announce.chain_tip_hash.is_some() { field_count += 1; }
    if announce.proposed_height.is_some() { field_count += 1; }
    if announce.proposed_hash.is_some() { field_count += 1; }
    if announce.chain_vote_weight.is_some() { field_count += 1; }
    if announce.min_fee_rate.is_some() { field_count += 1; }

    let mut buf = Vec::with_capacity(512);
    cbor::write_map(&mut buf, field_count);

    // Sorted keys alphabetically (21 total, 15 always + 6 conditional):
    // chain_id, chain_tip_hash(?), chain_tip_height(?), chain_vote_weight(?),
    // contact_email, country_code(?), host_address, identity_key,
    // network_name, node_name, node_role, org_name, org_type,
    // proposed_hash(?), proposed_height(?), software_version,
    // timestamp, version, wants_to_validate, wants_to_vote, website

    cbor::write_text(&mut buf, "chain_id");
    cbor::write_uint(&mut buf, announce.chain_id as u64);

    if let Some(ref h) = announce.chain_tip_hash {
        cbor::write_text(&mut buf, "chain_tip_hash");
        cbor::write_bytes(&mut buf, h);
    }

    if let Some(h) = announce.chain_tip_height {
        cbor::write_text(&mut buf, "chain_tip_height");
        cbor::write_uint(&mut buf, h);
    }

    if let Some(w) = announce.chain_vote_weight {
        cbor::write_text(&mut buf, "chain_vote_weight");
        cbor::write_uint(&mut buf, w);
    }

    cbor::write_text(&mut buf, "contact_email");
    match &announce.contact_email {
        Some(s) => cbor::write_text(&mut buf, s),
        None => cbor::write_null(&mut buf),
    }

    if let Some(ref cc) = announce.country_code {
        cbor::write_text(&mut buf, "country_code");
        cbor::write_text(&mut buf, cc);
    }

    cbor::write_text(&mut buf, "host_address");
    match &announce.host_address {
        Some(s) => cbor::write_text(&mut buf, s),
        None => cbor::write_null(&mut buf),
    }

    cbor::write_text(&mut buf, "identity_key");
    announce.identity_key.encode_wire(&mut buf);

    if let Some(rate) = announce.min_fee_rate {
        cbor::write_text(&mut buf, "min_fee_rate");
        cbor::write_uint(&mut buf, rate);
    }

    cbor::write_text(&mut buf, "network_name");
    cbor::write_text(&mut buf, &announce.network_name);

    cbor::write_text(&mut buf, "node_name");
    cbor::write_text(&mut buf, &announce.node_name);

    cbor::write_text(&mut buf, "node_role");
    cbor::write_uint(&mut buf, announce.node_role.wire_index() as u64);

    cbor::write_text(&mut buf, "org_name");
    match &announce.org_name {
        Some(s) => cbor::write_text(&mut buf, s),
        None => cbor::write_null(&mut buf),
    }

    cbor::write_text(&mut buf, "org_type");
    cbor::write_uint(&mut buf, announce.org_type.wire_index() as u64);

    if let Some(ref h) = announce.proposed_hash {
        cbor::write_text(&mut buf, "proposed_hash");
        cbor::write_bytes(&mut buf, h);
    }

    if let Some(h) = announce.proposed_height {
        cbor::write_text(&mut buf, "proposed_height");
        cbor::write_uint(&mut buf, h);
    }

    cbor::write_text(&mut buf, "software_version");
    cbor::write_text(&mut buf, &announce.software_version);

    cbor::write_text(&mut buf, "timestamp");
    cbor::write_uint(&mut buf, announce.timestamp);

    cbor::write_text(&mut buf, "version");
    cbor::write_uint(&mut buf, announce.version as u64);

    cbor::write_text(&mut buf, "wants_to_validate");
    cbor::write_bool(&mut buf, announce.wants_to_validate);

    cbor::write_text(&mut buf, "wants_to_vote");
    cbor::write_bool(&mut buf, announce.wants_to_vote);

    cbor::write_text(&mut buf, "website");
    match &announce.website {
        Some(s) => cbor::write_text(&mut buf, s),
        None => cbor::write_null(&mut buf),
    }

    buf
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::OutPoint;
    use noble_crypto::{Hash256, SCHEME_SECP256K1};

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
        let pk = NoblePublicKey::Secp256k1(vec![0xAA; 32]);
        let bytes = pk.wire_bytes();
        assert_eq!(bytes[0], 0x58);
        assert_eq!(bytes[1], 33);
        assert_eq!(bytes[2], SCHEME_SECP256K1);
        assert_eq!(&bytes[3..], &[0xAA; 32]);
    }

    #[test]
    fn signature_envelope_wire_bytes() {
        let sig = SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: vec![0xBB; 32],
            signature: vec![0xCC; 64],
        };
        let bytes = sig.wire_bytes();
        assert_eq!(bytes[0], 0x58);
        assert_eq!(bytes[1], 98);
        assert_eq!(bytes[2], SCHEME_SECP256K1);
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
        let pk = NoblePublicKey::Secp256k1(vec![0x42; 32]);
        assert_eq!(pk.wire_bytes(), pk.wire_bytes());

        let op = OutPoint { txid: Hash256::from_bytes([0xAB; 32]), vout: 42 };
        assert_eq!(op.wire_bytes(), op.wire_bytes());
    }

    #[test]
    fn encode_wire_matches_wire_bytes() {
        // Verify the default wire_bytes() wrapper matches direct encode_wire
        let pk = NoblePublicKey::Secp256k1(vec![0x42; 32]);
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
                address: NobleAddress::Noble(NoblePublicKey::Secp256k1(vec![0x42; 32])),
            }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: vec![0x42; 32],
                signature: vec![0x00; 64],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
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
            validator_id: NoblePublicKey::Secp256k1(vec![0x42; 32]),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
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
