// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Minimal deterministic CBOR encoder for the NOBLE protocol.
// Produces byte-identical output to noble-codec (Rust).
// FROZEN: do not modify encoding behavior.

#ifndef NOBLE_CBOR_H
#define NOBLE_CBOR_H

#include <stddef.h>
#include <stdint.h>

// Dynamic byte buffer for CBOR output.
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} noble_buf_t;

// Initialize a buffer with the given initial capacity.
void noble_buf_init(noble_buf_t *buf, size_t initial_cap);

// Free buffer memory.
void noble_buf_free(noble_buf_t *buf);

// Append raw bytes to the buffer.
void noble_buf_append(noble_buf_t *buf, const uint8_t *data, size_t len);

// Append a single byte.
void noble_buf_push(noble_buf_t *buf, uint8_t byte);

// CBOR encoding functions — match noble-codec/src/cbor.rs exactly.

// Write unsigned integer (major type 0).
void cbor_write_uint(noble_buf_t *buf, uint64_t value);

// Write byte string (major type 2).
void cbor_write_bytes(noble_buf_t *buf, const uint8_t *data, size_t len);

// Write UTF-8 text string (major type 3).
void cbor_write_text(noble_buf_t *buf, const char *str, size_t len);

// Write array header (major type 4). Caller writes len items after.
void cbor_write_array(noble_buf_t *buf, size_t len);

// Write map header (major type 5). Caller writes len key-value pairs after.
// Keys must be sorted alphabetically.
void cbor_write_map(noble_buf_t *buf, size_t len);

// Write boolean (major type 7, simple values 20/21).
void cbor_write_bool(noble_buf_t *buf, int value);

// Write null (major type 7, simple value 22).
void cbor_write_null(noble_buf_t *buf);

#endif // NOBLE_CBOR_H
