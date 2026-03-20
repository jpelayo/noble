// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// CMS/PKCS#7 per-field metadata signing for NOBLE.
// Single Rust implementation exposed as stable C ABI.
// All functions accept JSON input and return JSON output.
// Caller frees with noble_cms_free().

#ifndef NOBLE_CMS_H
#define NOBLE_CMS_H

#ifdef __cplusplus
extern "C" {
#endif

// Create a CMS/PKCS#7 detached signature over a metadata field value.
// Input JSON: { "private_key_hex": "<hex32>", "certificate_der_b64": "<base64>",
//               "field_value": "<string>", "algorithm": "p256"|"secp256k1" }
// Output JSON: { "cms_hex": "<der_hex>", "size": <uint> }
//         or:  { "error": "<message>" }
char *noble_sign_cms(const char *params_json);

// Verify a CMS/PKCS#7 detached signature.
// Input JSON: { "cms_hex": "<der_hex>", "field_value": "<string>",
//               "certificate_der_b64": "<base64>" (optional) }
// Output JSON: { "valid": <bool>, "signer_ski_hex": "<hex>",
//                "algorithm": "<name>", "error": "<message>"|null }
char *noble_verify_cms(const char *params_json);

// Parse a PKCS#12 container and extract the EC key + certificate.
// Input JSON: { "p12_hex": "<hex>", "password": "<string>" }
// Output JSON: { "public_key_hex": "<hex>", "algorithm": "p256"|"secp256k1",
//                "certificate_der_b64": "<base64>", "subject_name": "<string>",
//                "ski_hex": "<hex>", "private_key_hex": "<hex>" }
//         or:  { "error": "<message>" }
char *noble_import_pkcs12(const char *params_json);

// Free a string returned by any noble_cms_* function.
void noble_cms_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // NOBLE_CMS_H
