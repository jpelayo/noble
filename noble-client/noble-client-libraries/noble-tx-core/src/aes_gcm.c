// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Self-contained AES-256-GCM implementation for locked transaction encryption.
// AES-256 (FIPS 197) + GCM (NIST SP 800-38D).
// No external crypto dependencies — uses the project's own SHA-256 for key derivation.

#include "aes_gcm.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>

// ── AES-256 block cipher ──────────────────────────────────────────────

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

// Round constants for AES-256 key schedule (7 used, 10 allocated).
static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Multiply by x in GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1.
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// AES-256 key expansion: 32-byte key → 240-byte expanded key (60 words).
static void aes256_key_expand(const uint8_t key[32], uint8_t rk[240]) {
    memcpy(rk, key, 32);
    uint8_t temp[4];
    for (int i = 8; i < 60; i++) {
        memcpy(temp, &rk[(i - 1) * 4], 4);
        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i / 8 - 1];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        } else if (i % 8 == 4) {
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
        }
        rk[i * 4 + 0] = rk[(i - 8) * 4 + 0] ^ temp[0];
        rk[i * 4 + 1] = rk[(i - 8) * 4 + 1] ^ temp[1];
        rk[i * 4 + 2] = rk[(i - 8) * 4 + 2] ^ temp[2];
        rk[i * 4 + 3] = rk[(i - 8) * 4 + 3] ^ temp[3];
    }
}

// AES-256 encrypt a single 16-byte block in-place.
// State layout: column-major [row + 4*col].
static void aes256_encrypt_block(const uint8_t rk[240], uint8_t block[16]) {
    // Initial AddRoundKey
    for (int i = 0; i < 16; i++) block[i] ^= rk[i];

    for (int round = 1; round <= 14; round++) {
        uint8_t tmp[16];
        // SubBytes
        for (int i = 0; i < 16; i++) tmp[i] = SBOX[block[i]];

        // ShiftRows (column-major: state[row + 4*col])
        uint8_t sr[16];
        sr[0]  = tmp[0];  sr[4]  = tmp[4];  sr[8]  = tmp[8];  sr[12] = tmp[12];
        sr[1]  = tmp[5];  sr[5]  = tmp[9];  sr[9]  = tmp[13]; sr[13] = tmp[1];
        sr[2]  = tmp[10]; sr[6]  = tmp[14]; sr[10] = tmp[2];  sr[14] = tmp[6];
        sr[3]  = tmp[15]; sr[7]  = tmp[3];  sr[11] = tmp[7];  sr[15] = tmp[11];

        if (round < 14) {
            // MixColumns: multiply each column by [2,3,1,1] in GF(2^8)
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = sr[4*c], a1 = sr[4*c+1], a2 = sr[4*c+2], a3 = sr[4*c+3];
                block[4*c+0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
                block[4*c+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
                block[4*c+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
                block[4*c+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
            }
        } else {
            // Last round: no MixColumns
            memcpy(block, sr, 16);
        }

        // AddRoundKey
        const uint8_t *round_key = &rk[round * 16];
        for (int i = 0; i < 16; i++) block[i] ^= round_key[i];
    }
}

// ── GCM mode (NIST SP 800-38D) ───────────────────────────────────────

// GF(2^128) multiplication for GHASH.
// Uses the reducing polynomial P(x) = x^128 + x^7 + x^2 + x + 1.
// Bit numbering: MSB-first (bit 0 = MSB of byte 0).
// Algorithm 1 from NIST SP 800-38D.
static void ghash_mult(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t z[16], v[16];
    memset(z, 0, 16);
    memcpy(v, y, 16);

    for (int i = 0; i < 128; i++) {
        if (x[i / 8] & (1 << (7 - (i % 8)))) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j-1] & 1) << 7));
        }
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(out, z, 16);
}

// Increment the 32-bit big-endian counter in bytes [12..15].
static void inc_counter(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

// Core GCM: encrypt or decrypt with tag computation.
// If encrypting: writes ciphertext to out, computes tag.
// If decrypting: writes plaintext to out, computes tag for verification.
static void gcm_core(
    const uint8_t rk[240],
    const uint8_t nonce[12],
    const uint8_t *input, size_t len,
    uint8_t *output,
    uint8_t tag_out[16]
) {
    // H = AES_K(0^16)
    uint8_t H[16];
    memset(H, 0, 16);
    aes256_encrypt_block(rk, H);

    // J0 = nonce || 0x00000001
    uint8_t J0[16];
    memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // E(K, J0) for final tag XOR
    uint8_t EJ0[16];
    memcpy(EJ0, J0, 16);
    aes256_encrypt_block(rk, EJ0);

    // CTR mode encryption/decryption (counter starts at J0+1 = 2)
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);

    size_t full_blocks = len / 16;
    size_t remaining = len % 16;

    for (size_t i = 0; i < full_blocks; i++) {
        inc_counter(ctr);
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        aes256_encrypt_block(rk, keystream);
        for (int j = 0; j < 16; j++)
            output[i * 16 + j] = input[i * 16 + j] ^ keystream[j];
    }

    if (remaining > 0) {
        inc_counter(ctr);
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        aes256_encrypt_block(rk, keystream);
        for (size_t j = 0; j < remaining; j++)
            output[full_blocks * 16 + j] = input[full_blocks * 16 + j] ^ keystream[j];
    }

    // GHASH over ciphertext blocks (no AAD in our usage)
    // For encrypt: output IS the ciphertext
    // For decrypt: input IS the ciphertext — caller must pass the right pointer
    // We always GHASH over the OUTPUT of this function when encrypting,
    // but the caller handles this via the encrypt/decrypt wrappers below.
    // Here we just compute GHASH over whatever is in output (works for encrypt).
    // The decrypt wrapper handles it differently.

    // Note: tag computation always runs over CIPHERTEXT.
    // For encrypt: ciphertext = output. For decrypt: ciphertext = input.
    // This function is only called from the encrypt path — decrypt uses it differently.
    // We compute GHASH over output here (correct for encrypt).
    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);

    for (size_t i = 0; i < full_blocks; i++) {
        for (int j = 0; j < 16; j++) ghash_state[j] ^= output[i * 16 + j];
        uint8_t tmp[16];
        ghash_mult(ghash_state, H, tmp);
        memcpy(ghash_state, tmp, 16);
    }

    if (remaining > 0) {
        uint8_t last_block[16];
        memset(last_block, 0, 16);
        memcpy(last_block, &output[full_blocks * 16], remaining);
        for (int j = 0; j < 16; j++) ghash_state[j] ^= last_block[j];
        uint8_t tmp[16];
        ghash_mult(ghash_state, H, tmp);
        memcpy(ghash_state, tmp, 16);
    }

    // Length block: len(AAD)=0 || len(ciphertext) in bits, big-endian 64-bit
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t ct_bits = (uint64_t)len * 8;
    len_block[8]  = (uint8_t)(ct_bits >> 56);
    len_block[9]  = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);
    len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);
    len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >> 8);
    len_block[15] = (uint8_t)(ct_bits);

    for (int j = 0; j < 16; j++) ghash_state[j] ^= len_block[j];
    uint8_t final_ghash[16];
    ghash_mult(ghash_state, H, final_ghash);

    // Tag = GHASH XOR E(K, J0)
    for (int j = 0; j < 16; j++)
        tag_out[j] = final_ghash[j] ^ EJ0[j];

    // Zeroize sensitive material
    memset(H, 0, sizeof(H));
    memset(EJ0, 0, sizeof(EJ0));
}

// ── Public API ────────────────────────────────────────────────────────

int noble_aes_gcm_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *plaintext, size_t len,
    uint8_t *ciphertext_out, uint8_t tag_out[16]
) {
    uint8_t rk[240];
    aes256_key_expand(key, rk);
    gcm_core(rk, nonce, plaintext, len, ciphertext_out, tag_out);
    memset(rk, 0, sizeof(rk));
    return 0;
}

int noble_aes_gcm_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t len,
    const uint8_t tag[16], uint8_t *plaintext_out
) {
    uint8_t rk[240];
    aes256_key_expand(key, rk);

    // H = AES_K(0^16)
    uint8_t H[16];
    memset(H, 0, 16);
    aes256_encrypt_block(rk, H);

    // J0 = nonce || 0x00000001
    uint8_t J0[16];
    memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    // E(K, J0)
    uint8_t EJ0[16];
    memcpy(EJ0, J0, 16);
    aes256_encrypt_block(rk, EJ0);

    // Compute GHASH over CIPHERTEXT (before decryption)
    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);

    size_t full_blocks = len / 16;
    size_t remaining = len % 16;

    for (size_t i = 0; i < full_blocks; i++) {
        for (int j = 0; j < 16; j++) ghash_state[j] ^= ciphertext[i * 16 + j];
        uint8_t tmp[16];
        ghash_mult(ghash_state, H, tmp);
        memcpy(ghash_state, tmp, 16);
    }

    if (remaining > 0) {
        uint8_t last_block[16];
        memset(last_block, 0, 16);
        memcpy(last_block, &ciphertext[full_blocks * 16], remaining);
        for (int j = 0; j < 16; j++) ghash_state[j] ^= last_block[j];
        uint8_t tmp[16];
        ghash_mult(ghash_state, H, tmp);
        memcpy(ghash_state, tmp, 16);
    }

    // Length block
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t ct_bits = (uint64_t)len * 8;
    len_block[8]  = (uint8_t)(ct_bits >> 56);
    len_block[9]  = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);
    len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);
    len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >> 8);
    len_block[15] = (uint8_t)(ct_bits);

    for (int j = 0; j < 16; j++) ghash_state[j] ^= len_block[j];
    uint8_t final_ghash[16];
    ghash_mult(ghash_state, H, final_ghash);

    // Expected tag = GHASH XOR E(K, J0)
    uint8_t expected_tag[16];
    for (int j = 0; j < 16; j++)
        expected_tag[j] = final_ghash[j] ^ EJ0[j];

    // Verify tag (constant-time comparison)
    uint8_t diff = 0;
    for (int j = 0; j < 16; j++) diff |= expected_tag[j] ^ tag[j];

    if (diff != 0) {
        memset(rk, 0, sizeof(rk));
        memset(H, 0, sizeof(H));
        return -1; // Authentication failed
    }

    // Decrypt: CTR mode with counter starting at J0+1 = 2
    uint8_t ctr[16];
    memcpy(ctr, J0, 16);

    for (size_t i = 0; i < full_blocks; i++) {
        inc_counter(ctr);
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        aes256_encrypt_block(rk, keystream);
        for (int j = 0; j < 16; j++)
            plaintext_out[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
    }

    if (remaining > 0) {
        inc_counter(ctr);
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        aes256_encrypt_block(rk, keystream);
        for (size_t j = 0; j < remaining; j++)
            plaintext_out[full_blocks * 16 + j] = ciphertext[full_blocks * 16 + j] ^ keystream[j];
    }

    memset(rk, 0, sizeof(rk));
    memset(H, 0, sizeof(H));
    memset(EJ0, 0, sizeof(EJ0));
    return 0;
}

void noble_derive_lock_key(
    const uint8_t *password, size_t pw_len,
    const uint8_t *salt, size_t salt_len,
    uint8_t key_out[32]
) {
    // key = SHA-256(password || salt) — matches Rust locked_tx::derive_lock_key
    size_t total = pw_len + salt_len;
    uint8_t *preimage = (uint8_t *)malloc(total);
    if (!preimage) {
        // Fallback: zero key on allocation failure
        memset(key_out, 0, 32);
        return;
    }
    memcpy(preimage, password, pw_len);
    memcpy(preimage + pw_len, salt, salt_len);
    sha256(preimage, total, key_out);
    memset(preimage, 0, total);
    free(preimage);
}

// ── Platform-specific random bytes ────────────────────────────────────

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
int noble_random_bytes(uint8_t *out, size_t len) {
    arc4random_buf(out, len);
    return 0;
}
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
int noble_random_bytes(uint8_t *out, size_t len) {
    return BCryptGenRandom(NULL, out, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
#elif defined(__linux__)
#include <sys/random.h>
int noble_random_bytes(uint8_t *out, size_t len) {
    ssize_t got = getrandom(out, len, 0);
    return (got == (ssize_t)len) ? 0 : -1;
}
#else
#include <stdio.h>
int noble_random_bytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(out, 1, len, f);
    fclose(f);
    return got == len ? 0 : -1;
}
#endif
