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

// Build, sign, and CBOR-encode a transfer transaction.
// Input JSON: { "recipient": "<address_wire_hex>", "amount": <u64>,
//               "fee": <u64>, "utxos": [{"txid":"<hex>","vout":<u32>,"value":<u64>}, ...],
//               "change_address": "<wire_hex>", "private_key": "<hex32>",
//               "chain_id": <u32> }
// Output JSON: { "tx_hex": "<cbor_hex>", "tx_id": "<hash_hex>" }
//         or:  { "error": "<message>" }
char *noble_sign_transfer(const char *params_json);

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

// ── CMS/PKCS#7 Per-Field Metadata Signing ──

// Create a CMS/PKCS#7 detached signature over a field value.
// Input JSON: { "private_key_hex": "<hex32>", "certificate_der_b64": "<base64>",
//               "field_value": "<string>", "algorithm": "p256"|"secp256k1" }
// Output JSON: { "cms_hex": "<der_hex>", "size": <uint> }
//         or:  { "error": "<message>" }
char *noble_sign_cms_ffi(const char *params_json);

// Verify a CMS/PKCS#7 detached signature.
// Input JSON: { "cms_hex": "<der_hex>", "field_value": "<string>",
//               "certificate_der_b64": "<base64>" (optional) }
// Output JSON: { "valid": <bool>, "signer_ski_hex": "<hex>",
//                "algorithm": "<name>", "error": "<message>"|null }
char *noble_verify_cms_ffi(const char *params_json);

// Parse a PKCS#12 container and extract the EC key + certificate.
// Input JSON: { "p12_hex": "<hex>", "password": "<string>" }
// Output JSON: { "public_key_hex": "<hex>", "algorithm": "p256"|"secp256k1",
//                "certificate_der_b64": "<base64>", "subject_name": "<string>",
//                "ski_hex": "<hex>", "private_key_hex": "<hex>" }
//         or:  { "error": "<message>" }
char *noble_import_pkcs12_ffi(const char *params_json);

// Free a string returned by any noble_* function.
void noble_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // NOBLE_TX_H
