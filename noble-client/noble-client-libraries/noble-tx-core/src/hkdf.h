// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// HMAC-SHA256 and HKDF-SHA256 (RFC 5869).
// Used by ECIES for key derivation from ECDH shared secrets.

#ifndef NOBLE_HKDF_H
#define NOBLE_HKDF_H

#include <stdint.h>
#include <stddef.h>

// HMAC-SHA256: H(K XOR opad || H(K XOR ipad || message))
void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
);

// HKDF-Extract (RFC 5869 Section 2.2): PRK = HMAC-SHA256(salt, IKM)
void hkdf_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[32]
);

// HKDF-Expand (RFC 5869 Section 2.3): OKM = T(1) || T(2) || ...
// Only supports okm_len <= 32 (single block, sufficient for AES-256 key).
int hkdf_expand(
    const uint8_t prk[32],
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

// Convenience: HKDF-SHA256 extract-then-expand in one call.
// salt=NULL uses 32 zero bytes. okm_len must be <= 32.
int hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
);

#endif // NOBLE_HKDF_H
