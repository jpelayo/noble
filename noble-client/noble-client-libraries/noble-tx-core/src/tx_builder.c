// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Transaction CBOR serialization — byte-identical to noble-core wire format V1.
// Field order: alphabetical (ASCII lexicographic) by field name.
// FROZEN: matches noble-core/src/wire/v1.rs exactly.

#include "tx_builder.h"
#include <stdlib.h>
#include <string.h>

// ── Leaf type encoders ──────────────────────────────────────────────────

// Hash256: CBOR byte string, 32 bytes.
static void encode_hash256(noble_buf_t *buf, const uint8_t hash[HASH256_LEN]) {
    cbor_write_bytes(buf, hash, HASH256_LEN);
}

// OutPoint: map(2) { "txid": bytes, "vout": uint }
static void encode_outpoint(noble_buf_t *buf, const noble_outpoint_t *op) {
    cbor_write_map(buf, 2);
    cbor_write_text(buf, "txid", 4);
    encode_hash256(buf, op->txid);
    cbor_write_text(buf, "vout", 4);
    cbor_write_uint(buf, (uint64_t)op->vout);
}

// TxIn: map(1) { "prev_output": OutPoint }
static void encode_txin(noble_buf_t *buf, const noble_txin_t *inp) {
    cbor_write_map(buf, 1);
    cbor_write_text(buf, "prev_output", 11);
    encode_outpoint(buf, &inp->prev_output);
}

// NobleAddress: CBOR byte string (wire format: prefix + data).
static void encode_address_wire(noble_buf_t *buf, const noble_address_t *addr) {
    cbor_write_bytes(buf, addr->wire, addr->wire_len);
}

// TxOut for signing payload: map(2) { "address": wire_bytes, "value": uint }
// Uses raw wire bytes — matches noble-core wire/v1.rs signing payload.
static void encode_txout(noble_buf_t *buf, const noble_txout_t *out) {
    cbor_write_map(buf, 2);
    cbor_write_text(buf, "address", 7);
    encode_address_wire(buf, &out->address);
    cbor_write_text(buf, "value", 5);
    cbor_write_uint(buf, out->value);
}

// TxOut for full transaction: map(2) { "address": serde_enum, "value": uint }
// Uses serde enum encoding — matches Rust's #[derive(Deserialize)] on Transaction.
// The node deserializes submitted tx bytes with Transaction::from_cbor() which
// expects NobleAddress as a serde enum ({"Noble": {"Secp256k1": ...}} etc.),
// NOT raw wire bytes.
static void encode_txout_serde(noble_buf_t *buf, const noble_txout_t *out) {
    cbor_write_map(buf, 2);
    cbor_write_text(buf, "address", 7);
    tx_encode_address_serde(buf, &out->address);
    cbor_write_text(buf, "value", 5);
    cbor_write_uint(buf, out->value);
}

// MetadataEntry: map(2) { "key": text, "value": bytes }
static void encode_metadata(noble_buf_t *buf, const noble_metadata_t *m) {
    cbor_write_map(buf, 2);
    cbor_write_text(buf, "key", 3);
    cbor_write_text(buf, m->key, strlen(m->key));
    cbor_write_text(buf, "value", 5);
    cbor_write_bytes(buf, m->value, m->value_len);
}

// SignatureEnvelope: serde-compatible CBOR map matching Rust's
// #[derive(Serialize, Deserialize)] on SignatureEnvelope struct.
// Field order matches Rust struct DECLARATION order (serde preserves it):
//   scheme_id, public_key, signature
void tx_encode_sig_envelope(noble_buf_t *buf, const noble_sig_envelope_t *sig) {
    cbor_write_map(buf, 3);
    cbor_write_text(buf, "scheme_id", 9);
    cbor_write_uint(buf, (uint64_t)sig->scheme_id);
    cbor_write_text(buf, "public_key", 10);
    cbor_write_bytes(buf, sig->public_key, sig->public_key_len);
    cbor_write_text(buf, "signature", 9);
    cbor_write_bytes(buf, sig->signature, sig->signature_len);
}

// ── Full Transaction encoder ────────────────────────────────────────────
// Produces CBOR that Rust's Transaction::from_cbor() (serde) can deserialize.
// Key difference from signing payload: addresses use serde enum encoding
// ({"Noble": {"Secp256k1": ...}}) NOT raw wire bytes.

void tx_encode_full(noble_buf_t *buf, const noble_tx_t *tx) {
    // Count fields: 9 base + optional
    size_t field_count = 9;
    // contract_data: not supported in client transactions (omitted)
    // encrypted_locator: not supported in client transactions (omitted)
    if (tx->expires_at != 0)          field_count++;
    // external_attestations: not supported in client transactions (omitted)
    if (tx->gateway_address_len > 0)  field_count++;

    cbor_write_map(buf, field_count);

    // "additional_sigs"
    cbor_write_text(buf, "additional_sigs", 15);
    cbor_write_array(buf, tx->additional_sig_count);
    for (uint8_t i = 0; i < tx->additional_sig_count; i++) {
        tx_encode_sig_envelope(buf, &tx->additional_sigs[i]);
    }

    // "checksum"
    cbor_write_text(buf, "checksum", 8);
    encode_hash256(buf, tx->checksum);

    // "expires_at" — omitted when 0
    if (tx->expires_at != 0) {
        cbor_write_text(buf, "expires_at", 10);
        cbor_write_uint(buf, tx->expires_at);
    }

    // "gateway_address" — omitted when empty
    if (tx->gateway_address_len > 0) {
        cbor_write_text(buf, "gateway_address", 15);
        cbor_write_bytes(buf, tx->gateway_address, tx->gateway_address_len);
    }

    // "inputs"
    cbor_write_text(buf, "inputs", 6);
    cbor_write_array(buf, tx->input_count);
    for (uint8_t i = 0; i < tx->input_count; i++) {
        encode_txin(buf, &tx->inputs[i]);
    }

    // "issuer_sig"
    cbor_write_text(buf, "issuer_sig", 10);
    tx_encode_sig_envelope(buf, &tx->issuer_sig);

    // "metadata"
    cbor_write_text(buf, "metadata", 8);
    cbor_write_array(buf, tx->metadata_count);
    for (uint8_t i = 0; i < tx->metadata_count; i++) {
        encode_metadata(buf, &tx->metadata[i]);
    }

    // "outputs" — serde enum encoding for addresses.
    cbor_write_text(buf, "outputs", 7);
    cbor_write_array(buf, tx->output_count);
    for (uint8_t i = 0; i < tx->output_count; i++) {
        encode_txout_serde(buf, &tx->outputs[i]);
    }

    // "timestamp"
    cbor_write_text(buf, "timestamp", 9);
    cbor_write_uint(buf, tx->timestamp);

    // "tx_type"
    cbor_write_text(buf, "tx_type", 7);
    cbor_write_uint(buf, (uint64_t)tx->tx_type);

    // "version"
    cbor_write_text(buf, "version", 7);
    cbor_write_uint(buf, (uint64_t)tx->version);
}

// ── Signing Payload encoder ─────────────────────────────────────────────
// Matches noble-core/src/wire/v1.rs tx_signing_payload_bytes exactly.
// Key differences from full tx:
//   - Includes "chain_id" (not in full tx)
//   - Uses "input_outpoints" (direct OutPoints, not TxIn wrappers)
//   - No "issuer_sig" or "additional_sigs"
//   - Metadata sorted by key before encoding

// Canonical metadata ordering: by key, then by value.
//
// MIRRORS noble-core `metadata::canonical_cmp`. The value tiebreaker is
// load-bearing, not cosmetic: duplicate keys are legal, so comparing keys alone
// is NOT a total order — and qsort is not required to be stable, while Rust's
// sort is. Two entries sharing a key could therefore be ordered differently
// here than in Rust, producing a different signing payload (and so a different
// signature and tx_id) for the same transaction. Comparing the value removes
// the ambiguity in both languages without relying on sort stability.
//
// Values are length-prefixed byte strings, not NUL-terminated, so compare with
// memcmp over the shorter length and break ties on length.
static int metadata_cmp(const void *a, const void *b) {
    const noble_metadata_t *ma = (const noble_metadata_t *)a;
    const noble_metadata_t *mb = (const noble_metadata_t *)b;
    int k = strcmp(ma->key, mb->key);
    if (k != 0) return k;
    size_t n = ma->value_len < mb->value_len ? ma->value_len : mb->value_len;
    int v = memcmp(ma->value, mb->value, n);
    if (v != 0) return v;
    if (ma->value_len < mb->value_len) return -1;
    if (ma->value_len > mb->value_len) return 1;
    return 0;
}

// Sort a transaction's metadata into canonical order, in place.
//
// noble-core rejects a transaction whose metadata is not canonically ordered
// on the wire (T9b), because duplicate keys are legal and protocol readers take
// the FIRST match — so an in-transit reordering would change meaning while the
// signature still verified. Builders must therefore canonicalise BEFORE signing:
// the wire bytes and the signing payload have to agree.
void tx_canonicalize_metadata(noble_tx_t *tx) {
    if (tx == NULL || tx->metadata_count < 2) return;
    qsort(tx->metadata, tx->metadata_count, sizeof(noble_metadata_t), metadata_cmp);
}

void tx_encode_signing_payload(noble_buf_t *buf, const noble_tx_t *tx, uint32_t chain_id) {
    size_t field_count = 8;
    if (tx->declared_cosigner_count > 0) field_count++;
    if (tx->expires_at != 0)          field_count++;
    if (tx->gateway_address_len > 0)  field_count++;

    cbor_write_map(buf, field_count);

    // "chain_id"
    cbor_write_text(buf, "chain_id", 8);
    cbor_write_uint(buf, (uint64_t)chain_id);

    // "checksum"
    cbor_write_text(buf, "checksum", 8);
    encode_hash256(buf, tx->checksum);

    // "declared_cosigners" — omitted when empty (CS1). Alphabetically between
    // "checksum" and "expires_at". MIRRORS noble-core wire/v1.rs: an array of
    // wire-form public keys.
    if (tx->declared_cosigner_count > 0) {
        cbor_write_text(buf, "declared_cosigners", 18);
        cbor_write_array(buf, tx->declared_cosigner_count);
        for (uint8_t i = 0; i < tx->declared_cosigner_count; i++) {
            cbor_write_bytes(buf, tx->declared_cosigners[i], tx->declared_cosigner_lens[i]);
        }
    }

    // "expires_at" — omitted when 0
    if (tx->expires_at != 0) {
        cbor_write_text(buf, "expires_at", 10);
        cbor_write_uint(buf, tx->expires_at);
    }

    // "gateway_address" — omitted when empty
    if (tx->gateway_address_len > 0) {
        cbor_write_text(buf, "gateway_address", 15);
        cbor_write_bytes(buf, tx->gateway_address, tx->gateway_address_len);
    }

    // "input_outpoints" (NOT "inputs" — direct OutPoints without TxIn wrapper)
    cbor_write_text(buf, "input_outpoints", 15);
    cbor_write_array(buf, tx->input_count);
    for (uint8_t i = 0; i < tx->input_count; i++) {
        encode_outpoint(buf, &tx->inputs[i].prev_output);
    }

    // "metadata" — sorted by key before encoding
    noble_metadata_t sorted[MAX_METADATA];
    memcpy(sorted, tx->metadata, sizeof(noble_metadata_t) * tx->metadata_count);
    qsort(sorted, tx->metadata_count, sizeof(noble_metadata_t), metadata_cmp);

    cbor_write_text(buf, "metadata", 8);
    cbor_write_array(buf, tx->metadata_count);
    for (uint8_t i = 0; i < tx->metadata_count; i++) {
        encode_metadata(buf, &sorted[i]);
    }

    // "outputs"
    cbor_write_text(buf, "outputs", 7);
    cbor_write_array(buf, tx->output_count);
    for (uint8_t i = 0; i < tx->output_count; i++) {
        encode_txout(buf, &tx->outputs[i]);
    }

    // "timestamp"
    cbor_write_text(buf, "timestamp", 9);
    cbor_write_uint(buf, tx->timestamp);

    // "tx_type"
    cbor_write_text(buf, "tx_type", 7);
    cbor_write_uint(buf, (uint64_t)tx->tx_type);

    // "version"
    cbor_write_text(buf, "version", 7);
    cbor_write_uint(buf, (uint64_t)tx->version);
}

// ── Wire-format full transaction encoder ────────────────────────────────
// Produces CBOR matching noble-core/src/wire/v1.rs exactly.
// Used ONLY for tx_id computation (double_sha256(chain_id || wire_full)).
// Key differences from tx_encode_full (serde format):
//   - SignatureEnvelope → flat CBOR byte string, NOT map(3)
//   - NobleAddress → raw wire bytes, NOT serde enum map

// SignatureEnvelope in wire format: CBOR bytes([scheme_id || pk_len || pk || sig])
static void encode_sig_envelope_wire(noble_buf_t *buf, const noble_sig_envelope_t *sig) {
    size_t total = 1 + 1 + sig->public_key_len + sig->signature_len;
    uint8_t wire[1 + 1 + PUBKEY_LEN + SIG_LEN];
    wire[0] = sig->scheme_id;
    wire[1] = sig->public_key_len;
    memcpy(wire + 2, sig->public_key, sig->public_key_len);
    memcpy(wire + 2 + sig->public_key_len, sig->signature, sig->signature_len);
    cbor_write_bytes(buf, wire, total);
}

void tx_encode_wire_full(noble_buf_t *buf, const noble_tx_t *tx) {
    size_t field_count = 9;
    if (tx->declared_cosigner_count > 0) field_count++;
    if (tx->expires_at != 0)          field_count++;
    if (tx->gateway_address_len > 0)  field_count++;

    cbor_write_map(buf, field_count);

    // "additional_sigs" — wire format
    cbor_write_text(buf, "additional_sigs", 15);
    cbor_write_array(buf, tx->additional_sig_count);
    for (uint8_t i = 0; i < tx->additional_sig_count; i++) {
        encode_sig_envelope_wire(buf, &tx->additional_sigs[i]);
    }

    // "checksum"
    cbor_write_text(buf, "checksum", 8);
    encode_hash256(buf, tx->checksum);

    // "declared_cosigners" — omitted when empty (CS1). Alphabetically between
    // "checksum" and "expires_at". MIRRORS noble-core wire/v1.rs: an array of
    // wire-form public keys.
    if (tx->declared_cosigner_count > 0) {
        cbor_write_text(buf, "declared_cosigners", 18);
        cbor_write_array(buf, tx->declared_cosigner_count);
        for (uint8_t i = 0; i < tx->declared_cosigner_count; i++) {
            cbor_write_bytes(buf, tx->declared_cosigners[i], tx->declared_cosigner_lens[i]);
        }
    }

    // "expires_at" — omitted when 0
    if (tx->expires_at != 0) {
        cbor_write_text(buf, "expires_at", 10);
        cbor_write_uint(buf, tx->expires_at);
    }

    // "gateway_address" — omitted when empty
    if (tx->gateway_address_len > 0) {
        cbor_write_text(buf, "gateway_address", 15);
        cbor_write_bytes(buf, tx->gateway_address, tx->gateway_address_len);
    }

    // "inputs"
    cbor_write_text(buf, "inputs", 6);
    cbor_write_array(buf, tx->input_count);
    for (uint8_t i = 0; i < tx->input_count; i++) {
        encode_txin(buf, &tx->inputs[i]);
    }

    // "issuer_sig" — wire format
    cbor_write_text(buf, "issuer_sig", 10);
    encode_sig_envelope_wire(buf, &tx->issuer_sig);

    // "metadata"
    cbor_write_text(buf, "metadata", 8);
    cbor_write_array(buf, tx->metadata_count);
    for (uint8_t i = 0; i < tx->metadata_count; i++) {
        encode_metadata(buf, &tx->metadata[i]);
    }

    // "outputs" — wire format addresses
    cbor_write_text(buf, "outputs", 7);
    cbor_write_array(buf, tx->output_count);
    for (uint8_t i = 0; i < tx->output_count; i++) {
        encode_txout(buf, &tx->outputs[i]);
    }

    // "timestamp"
    cbor_write_text(buf, "timestamp", 9);
    cbor_write_uint(buf, tx->timestamp);

    // "tx_type"
    cbor_write_text(buf, "tx_type", 7);
    cbor_write_uint(buf, (uint64_t)tx->tx_type);

    // "version"
    cbor_write_text(buf, "version", 7);
    cbor_write_uint(buf, (uint64_t)tx->version);
}

// ── Address serde encoding (for JSON/bridge compatibility) ──────────────

void tx_encode_address_serde(noble_buf_t *buf, const noble_address_t *addr) {
    uint8_t prefix = addr->wire[0];
    const uint8_t *data = addr->wire + 1;
    size_t data_len = (size_t)(addr->wire_len - 1);

    switch (prefix) {
    case 0x02: // Noble secp256k1
        cbor_write_map(buf, 1);
        cbor_write_text(buf, "Noble", 5);
        cbor_write_map(buf, 1);
        cbor_write_text(buf, "Secp256k1", 9);
        cbor_write_bytes(buf, data, data_len);
        break;
    case 0x80: // Bitcoin Hash160
        cbor_write_map(buf, 1);
        cbor_write_text(buf, "BitcoinHash160", 14);
        cbor_write_bytes(buf, data, data_len);
        break;
    case 0x81: // Bitcoin Taproot
        cbor_write_map(buf, 1);
        cbor_write_text(buf, "BitcoinTaproot", 14);
        cbor_write_bytes(buf, data, data_len);
        break;
    }
}
