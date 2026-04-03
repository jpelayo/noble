// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Public API for noble-tx-core: transaction building, signing, and coin selection.
// All functions accept JSON input and return JSON output (caller frees with noble_free).
// Produces byte-identical CBOR to the node's noble-codec encoder.

#ifndef NOBLE_TX_H
#define NOBLE_TX_H

#ifdef __cplusplus
extern "C" {
#endif

// Unified transaction builder — handles transfer, split, join, and notarize in one function.
// Input JSON: { "mode": "transfer"|"split"|"join"|"notarize",
//               "private_key": "<hex32>", "chain_id": <u32>,
//               "change_address": "<wire_hex>", "fee_rate": <u64>,
//               "timestamp": <u64>,
//               "utxos": [{..., "status":"available"|...},...],  // full landscape
//               "selected_utxos": [{...},...],  // optional: pre-selected inputs
//               // mode-specific: recipient, amount, outputs, split_count, checksum, metadata
//             }
// Output JSON: { "tx_hex", "tx_id", "fee", "size" } or { "error" }
char *noble_build_transaction(const char *params_json);

// Build, sign, and CBOR-encode a transfer transaction.
// Input JSON: { "recipient": "<address_wire_hex>", "amount": <u64>,
//               "fee": <u64>, "utxos": [{"txid":"<hex>","vout":<u32>,"value":<u64>}, ...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
// Output JSON: { "tx_hex": "<cbor_hex>", "tx_id": "<hash_hex>" }
//         or:  { "error": "<message>" }
char *noble_sign_transfer(const char *params_json);

// Build, sign, and CBOR-encode a multi-output transfer (UTXO split/join).
// Input JSON: { "outputs": [{"address": "<wire_hex>", "amount": <u64>}, ...],
//               "fee_rate": <u64>, "utxos": [...], "change_address": "<wire_hex>",
//               "private_key": "<hex32>", "chain_id": <u32> }
// Output JSON: { "tx_hex": "<cbor_hex>", "tx_id": "<hash_hex>" }
char *noble_sign_split_transfer(const char *params_json);

// Build, sign, and CBOR-encode a notarization transaction.
// Input JSON: { "checksum": "<hex32>", "metadata": [{"key":"...","value":"..."},...],
//               "fee": <u64>, "utxos": [...], "change_address": "<wire_hex>",
//               "private_key": "<hex32>", "chain_id": <u32> }
// Output JSON: { "tx_hex": "<cbor_hex>", "tx_id": "<hash_hex>" }
char *noble_sign_notarization(const char *params_json);

// Run 5-pass coin selection.
// Input JSON: { "utxos": [...], "target": <u64> }
// Output JSON: { "selected": [...], "total": <u64>, "change": <u64> }
char *noble_select_utxos(const char *params_json);

// Encode a pre-built transaction to CBOR (no signing).
// Input JSON: full transaction fields including issuer_sig.
// Output JSON: { "tx_hex": "<cbor_hex>", "size": <uint> }
//         or:  { "error": "<message>" }
char *noble_tx_encode(const char *tx_json);

// Build, sign, and CBOR-encode a key rotation transaction (tx_type 0x02).
// Input JSON: { "new_pubkey_hex": "<hex>", "fee": <u64>, "utxos": [...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
// Output JSON: { "tx_hex": "<cbor_hex>", "tx_id": "<hash_hex>" }
char *noble_sign_key_rotation(const char *params_json);

// Build, sign, and CBOR-encode a badge proposal transaction (tx_type 0x03).
// Input JSON: { "target_pubkey": "<hex>", "proposal_type": "<string>",
//               "reason": "<string>", "fee": <u64>, "utxos": [...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
char *noble_sign_badge_proposal(const char *params_json);

// Build, sign, and CBOR-encode a badge vote transaction (tx_type 0x04).
// Input JSON: { "proposal_hash": "<hex64>", "vote": "approve"|"reject",
//               "fee": <u64>, "utxos": [...], "change_address": "<wire_hex>",
//               "private_key": "<hex32>", "chain_id": <u32> }
char *noble_sign_badge_vote(const char *params_json);

// Build, sign, and CBOR-encode a badge revocation transaction (tx_type 0x05).
// Input JSON: { "badge_id": "<string>", "fee": <u64>, "utxos": [...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
char *noble_sign_badge_revocation(const char *params_json);

// Build, sign, and CBOR-encode a locked notarization transaction (tx_type 0x06).
// Encrypts checksum and metadata values with AES-256-GCM using the password.
// Input JSON: { "checksum": "<hex64>", "password": "<string>",
//               "metadata": [{"key":"...","value":"..."},...],
//               "fee": <u64>, "utxos": [...], "change_address": "<wire_hex>",
//               "private_key": "<hex32>", "chain_id": <u32> }
char *noble_sign_locked(const char *params_json);

// Build, sign, and CBOR-encode an unlocking transaction (tx_type 0x07).
// Input JSON: { "locked_tx_id": "<hex64>", "password": "<string>",
//               "checksum": "<hex64>", "fee": <u64>, "utxos": [...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
char *noble_sign_unlocking(const char *params_json);

// Decode a CBOR-encoded transaction back to JSON.
// Input JSON: { "tx_hex": "<cbor_hex>" }
// Output JSON: { "version", "tx_type", "inputs", "outputs", "checksum",
//                "metadata", "issuer_sig", "additional_sigs", "timestamp", ... }
char *noble_tx_decode(const char *params_json);

// Decode a locked transaction and decrypt metadata with the given password.
// Input JSON: { "tx_hex": "<cbor_hex>", "password": "<string>" }
// Output JSON: same as noble_tx_decode plus "decrypted_checksum" and
//              "decrypted_metadata" with plaintext values.
char *noble_tx_decode_locked(const char *params_json);

// Verify the issuer_sig on a CBOR-encoded transaction.
// Input JSON: { "tx_hex": "<cbor_hex>", "chain_id": <u32> }
// Output JSON: { "valid": true/false, "signer": "<pubkey_hex>",
//                "tx_id": "<hash_hex>" }
char *noble_verify_tx(const char *params_json);

// Estimate the CBOR byte size of a transaction without submitting.
// Builds the transaction, signs it (probe pass), and returns the size.
// Input JSON: { "tx_type": "notarization"|"transfer"|"locked"|"unlocking",
//               ...same params as the corresponding noble_sign_* function... }
// Output JSON: { "size": <bytes> }
//         or:  { "error": "<message>" }
char *noble_estimate_tx_size(const char *params_json);

// ECIES single-recipient metadata field encryption (implemented in Rust, not C).
// Input JSON: { "plaintext_hex": "...", "recipient_pubkey_hex": "..." }
// Output JSON: { "payload_hex": "..." } or { "error": "..." }
// Compact binary: nonce(12) || ciphertext(N+16) || ephemeral(33) || encrypted_key(48) || key_nonce(12)
char *noble_ecies_encrypt(const char *params_json);

// ECIES single-recipient metadata field decryption (implemented in Rust, not C).
// Input JSON: { "payload_hex": "...", "private_key_hex": "..." }
// Output JSON: { "plaintext_hex": "..." } or { "error": "..." }
char *noble_ecies_decrypt(const char *params_json);

// CMS stubs (temporary — replaced by noble-cms-core XCFramework).
// Returns JSON error until noble-cms-core binary module is linked.
char *noble_sign_cms_ffi(const char *params_json);
char *noble_verify_cms_ffi(const char *params_json);
char *noble_import_pkcs12_ffi(const char *params_json);

// Free a string returned by any noble_* function.
void noble_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // NOBLE_TX_H
