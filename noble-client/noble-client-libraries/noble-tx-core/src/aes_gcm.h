// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// AES-256-GCM encryption for locked transactions (tx_type 0x06).
// Self-contained implementation — no external crypto dependencies.

#ifndef NOBLE_AES_GCM_H
#define NOBLE_AES_GCM_H

#include <stddef.h>
#include <stdint.h>

// Encrypt plaintext with AES-256-GCM.
// ciphertext_out must have space for len bytes.
// tag_out receives the 16-byte authentication tag.
// Returns 0 on success, -1 on failure.
int noble_aes_gcm_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *plaintext, size_t len,
    uint8_t *ciphertext_out, uint8_t tag_out[16]);

// Decrypt ciphertext with AES-256-GCM.
// plaintext_out must have space for len bytes.
// Returns 0 on success (tag valid), -1 on failure (tag mismatch).
int noble_aes_gcm_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t len,
    const uint8_t tag[16], uint8_t *plaintext_out);

// Derive encryption key from password + salt.
// key_out = SHA-256(password || salt)
void noble_derive_lock_key(
    const uint8_t *password, size_t pw_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t key_out[32]);

// Generate cryptographically random bytes (OS entropy).
// Returns 0 on success, -1 on failure.
int noble_random_bytes(uint8_t *out, size_t len);

#endif // NOBLE_AES_GCM_H
