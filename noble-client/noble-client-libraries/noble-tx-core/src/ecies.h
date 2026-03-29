// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Single-recipient ECIES encryption for metadata fields.
// secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM.
//
// Compact binary format:
//   nonce(12) || ciphertext(N+16) || ephemeral(33) || encrypted_key(48) || key_nonce(12)
//   Overhead: 121 bytes. Max plaintext for 256-byte metadata value: 135 bytes.
//
// Compatible with noble-crypto/src/ecies.rs (encrypt_single / decrypt_single).

#ifndef NOBLE_ECIES_H
#define NOBLE_ECIES_H

#include <stdint.h>
#include <stddef.h>

// ECIES overhead: nonce(12) + tag(16) + ephemeral(33) + enc_key(48) + key_nonce(12) = 121
#define ECIES_OVERHEAD 121

// Encrypt plaintext for a single secp256k1 recipient.
// payload_out must have capacity >= plaintext_len + ECIES_OVERHEAD.
// Returns actual payload length on success, or -1 on error.
int noble_ecies_encrypt_impl(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t recipient_pubkey[33],
    uint8_t *payload_out, size_t payload_out_cap
);

// Decrypt a compact ECIES payload with a secp256k1 private key.
// plaintext_out must have capacity >= payload_len - ECIES_OVERHEAD.
// Returns plaintext length on success, or -1 on error.
int noble_ecies_decrypt_impl(
    const uint8_t *payload, size_t payload_len,
    const uint8_t private_key[32],
    uint8_t *plaintext_out, size_t plaintext_out_cap
);

#endif // NOBLE_ECIES_H
