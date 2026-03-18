// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Standalone SHA-256 implementation. No external dependencies.

#ifndef NOBLE_SHA256_H
#define NOBLE_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

// Compute SHA-256 of data[0..len) into out[0..32).
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

// Double SHA-256: SHA-256(SHA-256(data)).
void double_sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

#endif // NOBLE_SHA256_H
