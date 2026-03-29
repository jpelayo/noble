// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Single-recipient ECIES for metadata field encryption.
// Matches noble-crypto/src/ecies.rs encrypt_single/decrypt_single exactly.

#include "ecies.h"
#include "hkdf.h"
#include "aes_gcm.h"
#include "sha256.h"
#include "hex.h"

#include <string.h>
#include <stdlib.h>
#include "secp256k1.h"
#include "secp256k1_ecdh.h"

// HKDF info string — must match noble-crypto/src/ecies.rs HKDF_INFO.
static const uint8_t HKDF_INFO[] = "noble-locator-v1";
static const size_t HKDF_INFO_LEN = 16;

// ── Helpers ──

// Generate cryptographically secure random bytes.
// Declared in aes_gcm.c (noble_random_bytes).
extern int noble_random_bytes(uint8_t *out, size_t len);

// Custom ECDH hash function: return raw x-coordinate (no SHA-256 hashing).
// Matches Rust k256::ecdh::diffie_hellman().raw_secret_bytes() which returns
// the raw x-coordinate of the ECDH point. The default secp256k1_ecdh_hash_function_sha256
// applies SHA-256(version_byte || x32) which produces a DIFFERENT value.
static int ecdh_hash_raw_x(unsigned char *output, const unsigned char *x32,
                            const unsigned char *y32, void *data) {
    (void)y32;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

// Check if 32 bytes are all zero (small-order point attack mitigation).
static int is_all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    return acc == 0;
}

// ── Encrypt ──

int noble_ecies_encrypt_impl(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t recipient_pubkey[33],
    uint8_t *payload_out, size_t payload_out_cap
) {
    size_t needed = plaintext_len + ECIES_OVERHEAD;
    if (payload_out_cap < needed) return -1;

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;

    // Parse recipient public key
    secp256k1_pubkey recipient_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &recipient_pk, recipient_pubkey, 33)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Generate random DEK (data encryption key)
    uint8_t dek[32];
    if (noble_random_bytes(dek, 32) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Encrypt plaintext with DEK: AES-256-GCM
    uint8_t data_nonce[12];
    if (noble_random_bytes(data_nonce, 12) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    // For empty plaintext, allocate 1 byte to avoid malloc(0) UB
    uint8_t *ciphertext = (uint8_t *)malloc(plaintext_len > 0 ? plaintext_len : 1);
    if (!ciphertext) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    uint8_t data_tag[16];
    if (noble_aes_gcm_encrypt(dek, data_nonce, plaintext, plaintext_len,
                               ciphertext, data_tag) != 0) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Generate ephemeral keypair
    uint8_t eph_secret[32];
    if (noble_random_bytes(eph_secret, 32) != 0) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    // Ensure valid scalar
    if (!secp256k1_ec_seckey_verify(ctx, eph_secret)) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_pubkey eph_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &eph_pubkey, eph_secret)) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Serialize ephemeral public key (SEC1 compressed, 33 bytes)
    uint8_t eph_pub_bytes[33];
    size_t eph_pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, eph_pub_bytes, &eph_pub_len,
                                  &eph_pubkey, SECP256K1_EC_COMPRESSED);

    // ECDH: shared_secret = ECDH(ephemeral_secret, recipient_pubkey)
    uint8_t shared_secret[32];
    if (!secp256k1_ecdh(ctx, shared_secret, &recipient_pk, eph_secret, ecdh_hash_raw_x, NULL)) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Reject all-zero shared secret (small-order point)
    if (is_all_zero(shared_secret, 32)) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // HKDF: derived_key = HKDF-SHA256(shared_secret, info="noble-locator-v1")
    uint8_t derived_key[32];
    if (hkdf_sha256(shared_secret, 32, NULL, 0, HKDF_INFO, HKDF_INFO_LEN,
                     derived_key, 32) != 0) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Encrypt DEK with derived key: AES-256-GCM
    uint8_t key_nonce[12];
    if (noble_random_bytes(key_nonce, 12) != 0) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }
    uint8_t encrypted_dek[32];
    uint8_t key_tag[16];
    if (noble_aes_gcm_encrypt(derived_key, key_nonce, dek, 32,
                               encrypted_dek, key_tag) != 0) {
        free(ciphertext);
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Pack compact binary: nonce(12) || ciphertext(N) || tag(16) || ephemeral(33) || encrypted_key(32) || key_tag(16) || key_nonce(12)
    // = nonce(12) || ciphertext_with_tag(N+16) || ephemeral(33) || encrypted_key_with_tag(48) || key_nonce(12)
    uint8_t *p = payload_out;
    memcpy(p, data_nonce, 12);              p += 12;
    memcpy(p, ciphertext, plaintext_len);   p += plaintext_len;
    memcpy(p, data_tag, 16);               p += 16;
    memcpy(p, eph_pub_bytes, 33);          p += 33;
    memcpy(p, encrypted_dek, 32);          p += 32;
    memcpy(p, key_tag, 16);               p += 16;
    memcpy(p, key_nonce, 12);             p += 12;

    free(ciphertext);
    secp256k1_context_destroy(ctx);

    return (int)needed;
}

// ── Decrypt ──

int noble_ecies_decrypt_impl(
    const uint8_t *payload, size_t payload_len,
    const uint8_t private_key[32],
    uint8_t *plaintext_out, size_t plaintext_out_cap
) {
    if (payload_len < ECIES_OVERHEAD) return -1;

    // total = nonce(12) + ciphertext(N+16) + ephemeral(33) + enc_key(48) + key_nonce(12) = N + 121
    size_t plaintext_len = payload_len - ECIES_OVERHEAD;

    if (plaintext_out_cap < plaintext_len) return -1;

    // Unpack compact binary
    const uint8_t *p = payload;
    const uint8_t *data_nonce = p;                          p += 12;
    const uint8_t *ciphertext = p;                          p += plaintext_len;
    const uint8_t *data_tag = p;                            p += 16;
    const uint8_t *eph_pub_bytes = p;                       p += 33;
    const uint8_t *encrypted_dek = p;                       p += 32;
    const uint8_t *key_tag = p;                             p += 16;
    const uint8_t *key_nonce = p;                           // p += 12;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;

    // Parse ephemeral public key
    secp256k1_pubkey eph_pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &eph_pk, eph_pub_bytes, 33)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // ECDH: shared_secret = ECDH(private_key, ephemeral_pubkey)
    uint8_t shared_secret[32];
    if (!secp256k1_ecdh(ctx, shared_secret, &eph_pk, private_key, ecdh_hash_raw_x, NULL)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    if (is_all_zero(shared_secret, 32)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // HKDF: derived_key
    uint8_t derived_key[32];
    if (hkdf_sha256(shared_secret, 32, NULL, 0, HKDF_INFO, HKDF_INFO_LEN,
                     derived_key, 32) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Decrypt DEK with derived key
    uint8_t dek[32];
    if (noble_aes_gcm_decrypt(derived_key, key_nonce, encrypted_dek, 32,
                               key_tag, dek) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Decrypt ciphertext with DEK
    if (noble_aes_gcm_decrypt(dek, data_nonce, ciphertext, plaintext_len,
                               data_tag, plaintext_out) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_context_destroy(ctx);
    return (int)plaintext_len;
}
