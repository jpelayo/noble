// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Canonical NOBLE metadata-field table + slot-0 schema-descriptor builder.
//
// PUBLIC API (declared in include/noble_tx.h):
//   - noble_metadata_registry_json()  → returns the table as JSON
//   - noble_build_metadata_array(json) → wraps a simple metadata array
//                                        with the slot-0 schema descriptor
//
// Both return malloc'd strings; caller frees with noble_free().

#include "metadata_fields.h"
#include "json.h"
#include "../include/noble_tx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── Canonical T-code table ────────────────────────────────────────────

static const noble_metadata_field_t TABLE[] = {
    {"doc:title",       "T01", "Document Title",     false, false},
    {"doc:description", "T02", "Description",        false, false},
    {"doc:batch",       "T03", "Batch Name",         false, true},
    {"doc:url",         "T04", "URL",                false, false},
    {"doc:bridge",      "T05", "Linked Document",    false, false},
    {"doc:relation",    "T06", "Relation",           false, false},
    {"doc:author",      "T07", "Author",             false, false},
    {"doc:publisher",   "T08", "Publisher",          false, false},
    {"signer:pubkey",   "T09", "Sender Public Key",  false, false},
    {"signer:email",    "T10", "Email",              true,  false},
    {"signer:phone",    "T11", "Phone",              true,  false},
    {"doc:type",        "T12", "Document Type",      false, false},
    {"doc:date",        "T13", "Date",               false, false},
    {"signer:url",      "T14", "Signer URL",         false, false},
    {"doc:download",    "T15", "Download URL",       false, false},
};

#define TABLE_LEN (sizeof(TABLE) / sizeof(TABLE[0]))

size_t noble_metadata_field_table(const noble_metadata_field_t **out) {
    if (out) *out = TABLE;
    return TABLE_LEN;
}

const char *noble_metadata_field_code(const char *key) {
    if (!key) return "T99";
    for (size_t i = 0; i < TABLE_LEN; i++) {
        if (strcmp(TABLE[i].key, key) == 0) return TABLE[i].code;
    }
    return "T99";  // custom / unknown
}

// ── Helpers ───────────────────────────────────────────────────────────

// Append `n` bytes of `src` to `*buf` at `*off`, growing `*cap` as needed.
// Returns 0 on success, -1 on OOM. The buffer remains valid on failure.
static int append_bytes(char **buf, size_t *off, size_t *cap, const char *src, size_t n) {
    if (*off + n + 1 > *cap) {
        size_t new_cap = (*off + n + 1) * 2;
        char *grown = (char *)realloc(*buf, new_cap);
        if (!grown) return -1;
        *buf = grown;
        *cap = new_cap;
    }
    memcpy(*buf + *off, src, n);
    *off += n;
    (*buf)[*off] = '\0';
    return 0;
}

static int append_str(char **buf, size_t *off, size_t *cap, const char *s) {
    return append_bytes(buf, off, cap, s, strlen(s));
}

// Append `s` JSON-escaped (escapes ", \, and control chars).
static int append_json_string(char **buf, size_t *off, size_t *cap, const char *s) {
    if (!s) s = "";
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            char tmp[2] = {'\\', (char)c};
            if (append_bytes(buf, off, cap, tmp, 2) < 0) return -1;
        } else if (c == '\n') {
            if (append_bytes(buf, off, cap, "\\n", 2) < 0) return -1;
        } else if (c == '\r') {
            if (append_bytes(buf, off, cap, "\\r", 2) < 0) return -1;
        } else if (c == '\t') {
            if (append_bytes(buf, off, cap, "\\t", 2) < 0) return -1;
        } else if (c < 0x20) {
            char tmp[8];
            int n = snprintf(tmp, sizeof(tmp), "\\u%04x", c);
            if (n < 0) return -1;
            if (append_bytes(buf, off, cap, tmp, (size_t)n) < 0) return -1;
        } else {
            if (append_bytes(buf, off, cap, (const char *)&c, 1) < 0) return -1;
        }
    }
    return 0;
}

static char *oom_error(void) {
    return json_emit_error("metadata builder: out of memory");
}

// ── Public: registry JSON ─────────────────────────────────────────────

char *noble_metadata_registry_json(void) {
    size_t cap = 4096;
    size_t off = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return oom_error();
    buf[0] = '\0';

    if (append_str(&buf, &off, &cap, "{\"fields\":[") < 0) goto oom;
    for (size_t i = 0; i < TABLE_LEN; i++) {
        if (i > 0 && append_str(&buf, &off, &cap, ",") < 0) goto oom;
        if (append_str(&buf, &off, &cap, "{\"key\":\"") < 0) goto oom;
        if (append_json_string(&buf, &off, &cap, TABLE[i].key) < 0) goto oom;
        if (append_str(&buf, &off, &cap, "\",\"code\":\"") < 0) goto oom;
        if (append_json_string(&buf, &off, &cap, TABLE[i].code) < 0) goto oom;
        if (append_str(&buf, &off, &cap, "\",\"label\":\"") < 0) goto oom;
        if (append_json_string(&buf, &off, &cap, TABLE[i].label) < 0) goto oom;
        if (append_str(&buf, &off, &cap,
                       TABLE[i].force_encrypt ? "\",\"force_encrypt\":true" : "\",\"force_encrypt\":false") < 0) goto oom;
        if (append_str(&buf, &off, &cap,
                       TABLE[i].plaintext_only ? ",\"plaintext_only\":true}" : ",\"plaintext_only\":false}") < 0) goto oom;
    }
    if (append_str(&buf, &off, &cap,
        "],\"rules\":{"
        "\"max_slots\":16,"
        "\"signed_consumes_two_slots\":true,"
        "\"pairings\":[[\"doc:bridge\",\"doc:relation\"]],"
        "\"unknown_key_code\":\"T99\""
        "}}") < 0) goto oom;
    return buf;

oom:
    free(buf);
    return oom_error();
}

// ── Public: schema-descriptor builder ─────────────────────────────────
//
// Input JSON: array of objects
//   [{ "key": "...", "value": "...", "mode": "plaintext"|"protected"|"encrypted",
//      "signed": bool? }, ...]
// Output JSON: array of objects with slot-0 schema prepended and SIG slots
// interleaved when "signed":true. SIG values are placeholders ("") that
// the caller (Swift bridge) fills in after CMS signing.
//
// Mode → (visibility, encoding) mapping:
//   plaintext  → pub:utf8
//   protected  → pwd:aesgcm  (host has already replaced value with hex ciphertext)
//   encrypted  → priv:ecies  (host has already replaced value with hex ciphertext)

char *noble_build_metadata_array(const char *params_json) {
    if (!params_json) return json_emit_error("metadata builder: null input");
    json_value_t *arr = json_parse(params_json);
    if (!arr || arr->type != JSON_ARRAY) {
        if (arr) json_free(arr);
        return json_emit_error("metadata builder: input must be a JSON array");
    }

    // Preallocate.
    size_t cap = 8192;
    size_t off = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { json_free(arr); return oom_error(); }
    buf[0] = '\0';

    // Build the schema descriptor first as a separate buffer so we can
    // emit it as the first array element.
    size_t schema_cap = 4096;
    size_t schema_off = 0;
    char *schema = (char *)malloc(schema_cap);
    if (!schema) { free(buf); json_free(arr); return oom_error(); }
    schema[0] = '\0';

    int slot = 1;
    int slot_budget = 16;  // 1 schema + 15 fields/sigs

    // Track slot → (key, value, sig_required) for later emission.
    typedef struct {
        const char *key;        // borrowed from arr (lifetime tied to arr)
        const char *value;      // borrowed from arr
        bool is_sig_placeholder;
    } slot_entry_t;
    size_t entry_cap = arr->array.count * 2 + 1;
    slot_entry_t *entries = (slot_entry_t *)calloc(entry_cap, sizeof(slot_entry_t));
    if (!entries) { free(schema); free(buf); json_free(arr); return oom_error(); }
    size_t n_entries = 0;

    // SIG slot keys are dynamic ("sig:<slot>") and need their own storage.
    // Use a simple bump-allocated arena.
    char *sig_keys_arena = (char *)malloc(arr->array.count * 16);
    if (!sig_keys_arena) {
        free(entries); free(schema); free(buf); json_free(arr); return oom_error();
    }
    size_t sig_arena_off = 0;

    for (size_t i = 0; i < arr->array.count; i++) {
        const json_value_t *e = &arr->array.items[i];
        if (e->type != JSON_OBJECT) continue;

        const char *key = json_get_string(e, "key");
        const char *value = json_get_string(e, "value");
        const char *mode = json_get_string(e, "mode");
        const json_value_t *signed_v = json_get(e, "signed");
        bool is_signed = signed_v && signed_v->type == JSON_BOOL && signed_v->boolean;

        if (!key || !*key) continue;
        if (!value) value = "";
        if (!mode || !*mode) mode = "plaintext";

        const char *code = noble_metadata_field_code(key);
        const char *vis;
        const char *enc;
        if (strcmp(mode, "encrypted") == 0)      { vis = "priv"; enc = "ecies"; }
        else if (strcmp(mode, "protected") == 0) { vis = "pwd";  enc = "aesgcm"; }
        else                                     { vis = "pub";  enc = "utf8"; }

        // Append to schema: "<sep><slot>:<code>:<vis>:<enc>:<key>"
        char line[512];
        int n = snprintf(line, sizeof(line),
                         "%s%d:%s:%s:%s:%s",
                         schema_off > 0 ? "\n" : "",
                         slot, code, vis, enc, key);
        if (n < 0 || (size_t)n >= sizeof(line)) {
            free(sig_keys_arena); free(entries); free(schema); free(buf);
            json_free(arr);
            return json_emit_error("metadata builder: line too long");
        }
        if (append_bytes(&schema, &schema_off, &schema_cap, line, (size_t)n) < 0) {
            free(sig_keys_arena); free(entries); free(schema); free(buf);
            json_free(arr);
            return oom_error();
        }

        if (slot + 1 > slot_budget) {
            free(sig_keys_arena); free(entries); free(schema); free(buf);
            json_free(arr);
            return json_emit_error("metadata exceeds 16-slot budget");
        }
        entries[n_entries].key = key;
        entries[n_entries].value = value;
        entries[n_entries].is_sig_placeholder = false;
        n_entries++;
        int field_slot = slot;
        slot++;

        if (is_signed) {
            if (slot + 1 > slot_budget) {
                free(sig_keys_arena); free(entries); free(schema); free(buf);
                json_free(arr);
                return json_emit_error("metadata exceeds 16-slot budget (signed entry needs an extra SIG slot)");
            }
            // Mint sig:<slot> key in the arena.
            char *sig_key = sig_keys_arena + sig_arena_off;
            int sn = snprintf(sig_key, 16, "sig:%d", field_slot);
            if (sn < 0 || sn >= 16) {
                free(sig_keys_arena); free(entries); free(schema); free(buf);
                json_free(arr);
                return json_emit_error("metadata builder: sig key encoding failed");
            }
            sig_arena_off += (size_t)sn + 1;

            int n2 = snprintf(line, sizeof(line),
                              "\n%d:SIG:pub:cms:%s", slot, sig_key);
            if (n2 < 0 || (size_t)n2 >= sizeof(line)) {
                free(sig_keys_arena); free(entries); free(schema); free(buf);
                json_free(arr);
                return json_emit_error("metadata builder: line too long");
            }
            if (append_bytes(&schema, &schema_off, &schema_cap, line, (size_t)n2) < 0) {
                free(sig_keys_arena); free(entries); free(schema); free(buf);
                json_free(arr);
                return oom_error();
            }
            entries[n_entries].key = sig_key;
            entries[n_entries].value = "";
            entries[n_entries].is_sig_placeholder = true;
            n_entries++;
            slot++;
        }
    }

    // Emit final JSON: [schema_entry, ...entries].
    if (append_str(&buf, &off, &cap, "{\"metadata\":[{\"key\":\"schema\",\"value\":\"") < 0) goto oom2;
    if (append_json_string(&buf, &off, &cap, schema) < 0) goto oom2;
    if (append_str(&buf, &off, &cap, "\",\"mode\":\"plaintext\"}") < 0) goto oom2;
    for (size_t i = 0; i < n_entries; i++) {
        if (append_str(&buf, &off, &cap, ",{\"key\":\"") < 0) goto oom2;
        if (append_json_string(&buf, &off, &cap, entries[i].key) < 0) goto oom2;
        if (append_str(&buf, &off, &cap, "\",\"value\":\"") < 0) goto oom2;
        if (append_json_string(&buf, &off, &cap, entries[i].value) < 0) goto oom2;
        if (append_str(&buf, &off, &cap, "\",\"mode\":\"plaintext\"") < 0) goto oom2;
        if (entries[i].is_sig_placeholder) {
            if (append_str(&buf, &off, &cap, ",\"is_sig\":true") < 0) goto oom2;
        }
        if (append_str(&buf, &off, &cap, "}") < 0) goto oom2;
    }
    if (append_str(&buf, &off, &cap, "]}") < 0) goto oom2;

    free(sig_keys_arena);
    free(entries);
    free(schema);
    json_free(arr);
    return buf;

oom2:
    free(sig_keys_arena);
    free(entries);
    free(schema);
    free(buf);
    json_free(arr);
    return oom_error();
}
