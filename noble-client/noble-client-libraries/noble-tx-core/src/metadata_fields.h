// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Canonical NOBLE notarization metadata-field catalog (T-codes).
//
// Single source of truth for the T-code table used by:
//   - Swift WebBridgeHandler (registerDocument)
//   - WRY Rust handlers (NobleDoc / NobleWin)
//   - The WebUI (eventually replacing the JS literal in documents.js)
//   - The MCP `getMetadataFieldRegistry` tool
//
// Adding a new field type means: append a row to TABLE in
// metadata_fields.c. Everything else (Layer 2 schema builder, Layer 5
// MCP tool, Layer 6 batch attachment) reads from this table.

#ifndef NOBLE_METADATA_FIELDS_H
#define NOBLE_METADATA_FIELDS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *key;          // canonical metadata key (e.g. "doc:title")
    const char *code;         // 3-char T-code (e.g. "T01")
    const char *label;        // human-readable label (e.g. "Document Title")
    bool force_encrypt;       // node rejects plaintext for this key (signer:email/phone)
    bool plaintext_only;      // must be plaintext mode (doc:batch)
} noble_metadata_field_t;

/// Returns the count of canonical fields and fills `*out_table` with a
/// pointer to the static table. Caller must NOT free.
size_t noble_metadata_field_table(const noble_metadata_field_t **out_table);

/// Lookup the T-code for a given metadata key. Returns "T99" for unknown
/// keys (custom user-supplied keys), per the canonical field convention.
const char *noble_metadata_field_code(const char *key);

#ifdef __cplusplus
}
#endif

#endif // NOBLE_METADATA_FIELDS_H
