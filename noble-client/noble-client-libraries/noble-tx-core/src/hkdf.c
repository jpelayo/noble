// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// HMAC-SHA256 and HKDF-SHA256 (RFC 5869).

#include "hkdf.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
) {
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];

    // If key > block size, hash it first
    uint8_t key_hash[SHA256_DIGEST_SIZE];
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = SHA256_DIGEST_SIZE;
    }

    // K XOR ipad
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }

    // Inner hash: SHA-256(K XOR ipad || data)
    // Manual two-step: hash k_pad, then data
    uint8_t inner_buf[SHA256_BLOCK_SIZE + 256]; // stack buffer for small data
    uint8_t *inner_alloc = NULL;
    uint8_t *inner_ptr;
    size_t inner_len = SHA256_BLOCK_SIZE + data_len;

    if (inner_len <= sizeof(inner_buf)) {
        inner_ptr = inner_buf;
    } else {
        inner_alloc = (uint8_t *)malloc(inner_len);
        if (!inner_alloc) return;
        inner_ptr = inner_alloc;
    }
    memcpy(inner_ptr, k_pad, SHA256_BLOCK_SIZE);
    memcpy(inner_ptr + SHA256_BLOCK_SIZE, data, data_len);
    sha256(inner_ptr, inner_len, inner_hash);
    if (inner_alloc) free(inner_alloc);

    // K XOR opad
    memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
    for (size_t i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }

    // Outer hash: SHA-256(K XOR opad || inner_hash)
    uint8_t outer_buf[SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE];
    memcpy(outer_buf, k_pad, SHA256_BLOCK_SIZE);
    memcpy(outer_buf + SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_SIZE);
    sha256(outer_buf, sizeof(outer_buf), out);
}

void hkdf_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t prk[32]
) {
    // RFC 5869 Section 2.2: PRK = HMAC-Hash(salt, IKM)
    // If salt not provided, use HashLen zero octets
    uint8_t default_salt[SHA256_DIGEST_SIZE];
    if (!salt || salt_len == 0) {
        memset(default_salt, 0, SHA256_DIGEST_SIZE);
        salt = default_salt;
        salt_len = SHA256_DIGEST_SIZE;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hkdf_expand(
    const uint8_t prk[32],
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    // RFC 5869 Section 2.3: T(1) = HMAC-Hash(PRK, info || 0x01)
    // We only support okm_len <= 32 (single HMAC block).
    if (okm_len > SHA256_DIGEST_SIZE) return -1;

    // T(1) = HMAC(PRK, info || 0x01)
    uint8_t t_input[256 + 1]; // info + counter byte
    uint8_t *t_alloc = NULL;
    uint8_t *t_ptr;
    size_t t_len = info_len + 1;

    if (t_len <= sizeof(t_input)) {
        t_ptr = t_input;
    } else {
        t_alloc = (uint8_t *)malloc(t_len);
        if (!t_alloc) return -1;
        t_ptr = t_alloc;
    }
    if (info_len > 0) memcpy(t_ptr, info, info_len);
    t_ptr[info_len] = 0x01; // counter = 1

    uint8_t t1[SHA256_DIGEST_SIZE];
    hmac_sha256(prk, SHA256_DIGEST_SIZE, t_ptr, t_len, t1);
    memcpy(okm, t1, okm_len);

    if (t_alloc) free(t_alloc);
    return 0;
}

int hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len
) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    return hkdf_expand(prk, info, info_len, okm, okm_len);
}
