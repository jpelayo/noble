// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// CBOR decoder for transaction parsing (decode direction).
// Complements cbor.c (encoder). Does NOT modify the frozen encoder.

#ifndef NOBLE_CBOR_DECODE_H
#define NOBLE_CBOR_DECODE_H

#include <stddef.h>
#include <stdint.h>

// CBOR major types
#define CBOR_MAJOR_UINT   0
#define CBOR_MAJOR_NEGINT 1
#define CBOR_MAJOR_BYTES  2
#define CBOR_MAJOR_TEXT   3
#define CBOR_MAJOR_ARRAY  4
#define CBOR_MAJOR_MAP    5
#define CBOR_MAJOR_TAG    6
#define CBOR_MAJOR_SIMPLE 7

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} cbor_reader_t;

// Initialize a CBOR reader over a byte buffer.
void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len);

// Read the next CBOR item header. Returns major type and argument value.
// Returns 0 on success, -1 on error (truncated data).
int cbor_read_header(cbor_reader_t *r, uint8_t *major_out, uint64_t *value_out);

// Peek at the next major type without consuming it. Returns -1 if at end.
int cbor_peek_major(cbor_reader_t *r);

// Read unsigned integer (major type 0).
int cbor_read_uint(cbor_reader_t *r, uint64_t *out);

// Read byte string. Sets *data to point inside the reader buffer, sets *len.
// The pointer is valid as long as the reader's underlying buffer is alive.
int cbor_read_bytes(cbor_reader_t *r, const uint8_t **data, size_t *len);

// Read text string. Sets *str (NOT null-terminated), *len.
int cbor_read_text(cbor_reader_t *r, const char **str, size_t *len);

// Read map header. Returns number of key-value pairs via *count.
int cbor_read_map(cbor_reader_t *r, size_t *count);

// Read array header. Returns number of items via *count.
int cbor_read_array(cbor_reader_t *r, size_t *count);

// Skip the next CBOR item (including nested structures).
int cbor_skip(cbor_reader_t *r);

#endif // NOBLE_CBOR_DECODE_H
