// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

#include "hex.h"

static const char HEX_CHARS[] = "0123456789abcdef";

void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX_CHARS[data[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap) {
    if (hex_len % 2 != 0) return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > out_cap) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)byte_len;
}
