// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// CBOR decoder — reads RFC 8949 deterministic CBOR produced by the encoder.

#include "cbor_decode.h"
#include <string.h>

void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

int cbor_read_header(cbor_reader_t *r, uint8_t *major_out, uint64_t *value_out) {
    if (r->pos >= r->len) return -1;
    uint8_t initial = r->data[r->pos++];
    *major_out = (initial >> 5) & 0x07;
    uint8_t additional = initial & 0x1f;

    if (additional < 24) {
        *value_out = additional;
    } else if (additional == 24) {
        if (r->pos >= r->len) return -1;
        *value_out = r->data[r->pos++];
    } else if (additional == 25) {
        if (r->pos + 2 > r->len) return -1;
        *value_out = ((uint64_t)r->data[r->pos] << 8) | r->data[r->pos + 1];
        r->pos += 2;
    } else if (additional == 26) {
        if (r->pos + 4 > r->len) return -1;
        *value_out = ((uint64_t)r->data[r->pos] << 24)
                   | ((uint64_t)r->data[r->pos + 1] << 16)
                   | ((uint64_t)r->data[r->pos + 2] << 8)
                   | r->data[r->pos + 3];
        r->pos += 4;
    } else if (additional == 27) {
        if (r->pos + 8 > r->len) return -1;
        *value_out = ((uint64_t)r->data[r->pos] << 56)
                   | ((uint64_t)r->data[r->pos + 1] << 48)
                   | ((uint64_t)r->data[r->pos + 2] << 40)
                   | ((uint64_t)r->data[r->pos + 3] << 32)
                   | ((uint64_t)r->data[r->pos + 4] << 24)
                   | ((uint64_t)r->data[r->pos + 5] << 16)
                   | ((uint64_t)r->data[r->pos + 6] << 8)
                   | r->data[r->pos + 7];
        r->pos += 8;
    } else {
        return -1; // Indefinite length or reserved — not used in Noble CBOR
    }
    return 0;
}

int cbor_peek_major(cbor_reader_t *r) {
    if (r->pos >= r->len) return -1;
    return (r->data[r->pos] >> 5) & 0x07;
}

int cbor_read_uint(cbor_reader_t *r, uint64_t *out) {
    uint8_t major;
    if (cbor_read_header(r, &major, out) != 0) return -1;
    if (major != CBOR_MAJOR_UINT) return -1;
    return 0;
}

int cbor_read_bytes(cbor_reader_t *r, const uint8_t **data, size_t *len) {
    uint8_t major;
    uint64_t val;
    if (cbor_read_header(r, &major, &val) != 0) return -1;
    if (major != CBOR_MAJOR_BYTES) return -1;
    if (r->pos + val > r->len) return -1;
    *data = r->data + r->pos;
    *len = (size_t)val;
    r->pos += (size_t)val;
    return 0;
}

int cbor_read_text(cbor_reader_t *r, const char **str, size_t *len) {
    uint8_t major;
    uint64_t val;
    if (cbor_read_header(r, &major, &val) != 0) return -1;
    if (major != CBOR_MAJOR_TEXT) return -1;
    if (r->pos + val > r->len) return -1;
    *str = (const char *)(r->data + r->pos);
    *len = (size_t)val;
    r->pos += (size_t)val;
    return 0;
}

int cbor_read_map(cbor_reader_t *r, size_t *count) {
    uint8_t major;
    uint64_t val;
    if (cbor_read_header(r, &major, &val) != 0) return -1;
    if (major != CBOR_MAJOR_MAP) return -1;
    *count = (size_t)val;
    return 0;
}

int cbor_read_array(cbor_reader_t *r, size_t *count) {
    uint8_t major;
    uint64_t val;
    if (cbor_read_header(r, &major, &val) != 0) return -1;
    if (major != CBOR_MAJOR_ARRAY) return -1;
    *count = (size_t)val;
    return 0;
}

int cbor_skip(cbor_reader_t *r) {
    uint8_t major;
    uint64_t val;
    if (cbor_read_header(r, &major, &val) != 0) return -1;

    switch (major) {
    case CBOR_MAJOR_UINT:
    case CBOR_MAJOR_NEGINT:
    case CBOR_MAJOR_SIMPLE:
        // Already consumed by read_header
        return 0;
    case CBOR_MAJOR_BYTES:
    case CBOR_MAJOR_TEXT:
        if (r->pos + val > r->len) return -1;
        r->pos += (size_t)val;
        return 0;
    case CBOR_MAJOR_ARRAY:
        for (uint64_t i = 0; i < val; i++) {
            if (cbor_skip(r) != 0) return -1;
        }
        return 0;
    case CBOR_MAJOR_MAP:
        for (uint64_t i = 0; i < val; i++) {
            if (cbor_skip(r) != 0) return -1; // key
            if (cbor_skip(r) != 0) return -1; // value
        }
        return 0;
    case CBOR_MAJOR_TAG:
        return cbor_skip(r); // skip the tagged value
    default:
        return -1;
    }
}
