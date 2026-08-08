// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Transaction structure and CBOR serialization.
// Produces byte-identical output to noble-core + noble-codec.

#ifndef NOBLE_TX_BUILDER_H
#define NOBLE_TX_BUILDER_H

#include "cbor.h"
#include <stdint.h>

#define MAX_TX_SIZE    8192
#define MAX_INPUTS     64
#define MAX_OUTPUTS    64
#define MAX_METADATA   16
#define MAX_SIGS       16
#define HASH256_LEN    32
#define PUBKEY_LEN     33
#define SIG_LEN        64

// ── Data types matching noble-core structs ──────────────────────────────

typedef struct {
    uint8_t txid[HASH256_LEN];
    uint32_t vout;
} noble_outpoint_t;

typedef struct {
    noble_outpoint_t prev_output;
} noble_txin_t;

// Address wire format: prefix byte + data.
// 0x02 + 33 bytes (Noble secp256k1)
// 0x80 + 20 bytes (Bitcoin Hash160)
// 0x81 + 32 bytes (Bitcoin Taproot)
typedef struct {
    uint8_t wire[34]; // max size: 1 prefix + 33 key bytes
    uint8_t wire_len;
} noble_address_t;

typedef struct {
    noble_address_t address;
    uint64_t value;
} noble_txout_t;

typedef struct {
    uint8_t scheme_id;
    uint8_t public_key[PUBKEY_LEN];
    uint8_t public_key_len;
    uint8_t signature[SIG_LEN];
    uint8_t signature_len;
} noble_sig_envelope_t;

typedef struct {
    char    key[65];      // null-terminated, max 64 chars
    uint8_t value[257];   // max 256 bytes
    uint16_t value_len;
} noble_metadata_t;

typedef struct {
    uint16_t version;
    uint8_t  tx_type;
    noble_txin_t inputs[MAX_INPUTS];
    uint8_t      input_count;
    noble_txout_t outputs[MAX_OUTPUTS];
    uint8_t       output_count;
    uint8_t  checksum[HASH256_LEN];
    uint64_t timestamp;
    noble_sig_envelope_t issuer_sig;
    noble_sig_envelope_t additional_sigs[MAX_SIGS];
    uint8_t              additional_sig_count;
    // CS1: keys the issuer permits to co-sign, in wire form
    // [scheme_id || key_bytes]. Covered by the signing payload, so the issuer
    // commits to WHO may ever appear on the record. Empty (count 0) means no
    // co-signatures are accepted — and is then omitted from the encoding, so a
    // transaction that declares none encodes exactly as before.
    // MIRRORS noble-core `Transaction::declared_cosigners`.
    uint8_t  declared_cosigners[MAX_SIGS][34];
    uint8_t  declared_cosigner_lens[MAX_SIGS];
    uint8_t  declared_cosigner_count;
    noble_metadata_t metadata[MAX_METADATA];
    uint8_t          metadata_count;
    uint8_t  gateway_address[34];
    uint8_t  gateway_address_len; // 0 = not present
    uint64_t expires_at;          // 0 = not present
} noble_tx_t;

// ── Serialization functions ─────────────────────────────────────────────

// Encode a full Transaction to CBOR (for wire transmission / tx_id computation).
void tx_encode_full(noble_buf_t *buf, const noble_tx_t *tx);

// Encode a TxSigningPayload to CBOR (for signing message computation).
// chain_id is included in the payload but NOT in the full transaction.
// Sort tx->metadata into canonical order (by key, then value), in place.
//
// MUST be called before signing: noble-core rejects a transaction whose
// metadata is not canonically ordered on the wire (T9b), and the signing
// payload must describe the same order the wire carries.
void tx_canonicalize_metadata(noble_tx_t *tx);

void tx_encode_signing_payload(noble_buf_t *buf, const noble_tx_t *tx, uint32_t chain_id);

// Encode a NobleAddress in serde enum format:
//   Noble/Secp256k1 → {"Noble": {"Secp256k1": <bytes>}}
//   BitcoinHash160  → {"BitcoinHash160": <bytes>}
//   BitcoinTaproot  → {"BitcoinTaproot": <bytes>}
void tx_encode_address_serde(noble_buf_t *buf, const noble_address_t *addr);

// Encode a SignatureEnvelope as a serde-compatible CBOR map (transport format).
void tx_encode_sig_envelope(noble_buf_t *buf, const noble_sig_envelope_t *sig);

// Encode a full Transaction in wire format (for tx_id computation).
// Matches noble-core/src/wire/v1.rs exactly: SignatureEnvelope as byte string,
// NobleAddress as raw wire bytes. NOT for transport (use tx_encode_full for that).
void tx_encode_wire_full(noble_buf_t *buf, const noble_tx_t *tx);

#endif // NOBLE_TX_BUILDER_H
