// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef NOBLE_HEX_H
#define NOBLE_HEX_H

#include <stddef.h>
#include <stdint.h>

// Encode binary data to lowercase hex string.
// out must have space for len*2 + 1 bytes (null-terminated).
void hex_encode(const uint8_t *data, size_t len, char *out);

// Decode hex string to binary. Returns number of bytes written, or -1 on error.
// out must have space for strlen(hex)/2 bytes.
int hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap);

#endif // NOBLE_HEX_H
