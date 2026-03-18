// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Minimal deterministic CBOR encoder for the NOBLE protocol.
// Mirrors noble-codec/src/cbor.rs write_header / write_* functions exactly.
// FROZEN: do not modify encoding behavior.

#include "cbor.h"
#include <stdlib.h>
#include <string.h>

// CBOR major types (3-bit prefix in the first byte).
#define MAJOR_UINT   0  // Major type 0: unsigned integer
#define MAJOR_BYTES  2  // Major type 2: byte string
#define MAJOR_TEXT   3  // Major type 3: UTF-8 text string
#define MAJOR_ARRAY  4  // Major type 4: array
#define MAJOR_MAP    5  // Major type 5: map
#define MAJOR_SIMPLE 7  // Major type 7: simple values

// ── Buffer operations ───────────────────────────────────────────────────

void noble_buf_init(noble_buf_t *buf, size_t initial_cap) {
    buf->data = (uint8_t *)malloc(initial_cap > 0 ? initial_cap : 256);
    buf->len = 0;
    buf->cap = initial_cap > 0 ? initial_cap : 256;
}

void noble_buf_free(noble_buf_t *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static void buf_ensure(noble_buf_t *buf, size_t additional) {
    if (buf->len + additional > buf->cap) {
        size_t new_cap = buf->cap * 2;
        while (new_cap < buf->len + additional)
            new_cap *= 2;
        buf->data = (uint8_t *)realloc(buf->data, new_cap);
        buf->cap = new_cap;
    }
}

void noble_buf_push(noble_buf_t *buf, uint8_t byte) {
    buf_ensure(buf, 1);
    buf->data[buf->len++] = byte;
}

void noble_buf_append(noble_buf_t *buf, const uint8_t *data, size_t len) {
    buf_ensure(buf, len);
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
}

// ── CBOR header encoding ────────────────────────────────────────────────
// RFC 8949 Section 3.1: minimal encoding.
// Must match noble-codec/src/cbor.rs write_header() exactly.

static void write_header(noble_buf_t *buf, uint8_t major, uint64_t value) {
    uint8_t prefix = (uint8_t)(major << 5);
    if (value < 24) {
        noble_buf_push(buf, prefix | (uint8_t)value);
    } else if (value <= 0xFF) {
        noble_buf_push(buf, prefix | 24);
        noble_buf_push(buf, (uint8_t)value);
    } else if (value <= 0xFFFF) {
        noble_buf_push(buf, prefix | 25);
        noble_buf_push(buf, (uint8_t)(value >> 8));
        noble_buf_push(buf, (uint8_t)(value));
    } else if (value <= 0xFFFFFFFF) {
        noble_buf_push(buf, prefix | 26);
        noble_buf_push(buf, (uint8_t)(value >> 24));
        noble_buf_push(buf, (uint8_t)(value >> 16));
        noble_buf_push(buf, (uint8_t)(value >> 8));
        noble_buf_push(buf, (uint8_t)(value));
    } else {
        noble_buf_push(buf, prefix | 27);
        noble_buf_push(buf, (uint8_t)(value >> 56));
        noble_buf_push(buf, (uint8_t)(value >> 48));
        noble_buf_push(buf, (uint8_t)(value >> 40));
        noble_buf_push(buf, (uint8_t)(value >> 32));
        noble_buf_push(buf, (uint8_t)(value >> 24));
        noble_buf_push(buf, (uint8_t)(value >> 16));
        noble_buf_push(buf, (uint8_t)(value >> 8));
        noble_buf_push(buf, (uint8_t)(value));
    }
}

// ── Public CBOR write functions ─────────────────────────────────────────

void cbor_write_uint(noble_buf_t *buf, uint64_t value) {
    write_header(buf, MAJOR_UINT, value);
}

void cbor_write_bytes(noble_buf_t *buf, const uint8_t *data, size_t len) {
    write_header(buf, MAJOR_BYTES, (uint64_t)len);
    noble_buf_append(buf, data, len);
}

void cbor_write_text(noble_buf_t *buf, const char *str, size_t len) {
    write_header(buf, MAJOR_TEXT, (uint64_t)len);
    noble_buf_append(buf, (const uint8_t *)str, len);
}

void cbor_write_array(noble_buf_t *buf, size_t len) {
    write_header(buf, MAJOR_ARRAY, (uint64_t)len);
}

void cbor_write_map(noble_buf_t *buf, size_t len) {
    write_header(buf, MAJOR_MAP, (uint64_t)len);
}

void cbor_write_bool(noble_buf_t *buf, int value) {
    noble_buf_push(buf, (uint8_t)((MAJOR_SIMPLE << 5) | (value ? 21 : 20)));
}

void cbor_write_null(noble_buf_t *buf) {
    noble_buf_push(buf, (uint8_t)((MAJOR_SIMPLE << 5) | 22));
}
