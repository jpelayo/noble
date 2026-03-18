// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Minimal JSON parser/emitter for noble-tx-core.
// Only supports the subset needed for transaction parameter parsing.

#ifndef NOBLE_JSON_H
#define NOBLE_JSON_H

#include <stddef.h>
#include <stdint.h>

// JSON value types.
typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

// Forward declaration.
typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    union {
        int         boolean;
        double      number;
        struct { char *str; size_t len; } string;
        struct { json_value_t *items; size_t count; } array;
        struct { char **keys; json_value_t *values; size_t count; } object;
    };
};

// Parse a JSON string. Returns NULL on failure.
// Caller must free with json_free().
json_value_t *json_parse(const char *input);

// Free a parsed JSON value tree.
void json_free(json_value_t *val);

// Object field lookup. Returns NULL if not found or wrong type.
const json_value_t *json_get(const json_value_t *obj, const char *key);
const char         *json_get_string(const json_value_t *obj, const char *key);
uint64_t            json_get_uint(const json_value_t *obj, const char *key);
uint32_t            json_get_uint32(const json_value_t *obj, const char *key);

// Build a JSON output string. Caller must free() the result.
char *json_emit_result(const char *tx_hex, const char *tx_id);
char *json_emit_error(const char *message);

#endif // NOBLE_JSON_H
