// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Transaction signing: compute signing message, sign with secp256k1,
// compute tx_id.

#ifndef NOBLE_SIGNING_H
#define NOBLE_SIGNING_H

#include "tx_builder.h"
#include "sha256.h"
#include <stdint.h>

// Compute the signing message for a transaction:
//   SHA-256(cbor_encode(signing_payload))
void compute_signing_message(
    const noble_tx_t *tx,
    uint32_t chain_id,
    uint8_t out[SHA256_DIGEST_SIZE]
);

// Sign a 32-byte message with a secp256k1 private key.
// private_key: 32 bytes. signature_out: 64 bytes (r || s compact).
// Returns 0 on success, -1 on failure.
int secp256k1_sign_message(
    const uint8_t private_key[32],
    const uint8_t message[32],
    uint8_t signature_out[64]
);

// Derive the compressed public key (33 bytes) from a 32-byte private key.
// Returns 0 on success, -1 on failure.
int secp256k1_derive_pubkey(
    const uint8_t private_key[32],
    uint8_t pubkey_out[33]
);

// Compute the transaction ID:
//   SHA-256(chain_id_be_4bytes || cbor_encode(full_tx))
void compute_tx_id(
    const noble_tx_t *tx,
    uint32_t chain_id,
    uint8_t out[SHA256_DIGEST_SIZE]
);

// Full sign-and-encode pipeline:
// 1. Compute signing message
// 2. Sign with private key
// 3. Fill issuer_sig
// 4. Encode full transaction
// 5. Reject if serialized size > MAX_TX_SIZE
// 6. Compute tx_id
// Returns 0 on success, -1 on signing failure, -2 if tx exceeds MAX_TX_SIZE.
int sign_and_encode_tx(
    noble_tx_t *tx,
    const uint8_t private_key[32],
    uint32_t chain_id,
    noble_buf_t *tx_cbor_out,
    uint8_t tx_id_out[SHA256_DIGEST_SIZE]
);

// Verify a secp256k1 signature over a 32-byte message.
// pubkey: 33-byte compressed public key.
// message: 32-byte digest.
// signature: 64-byte compact (r || s).
// Returns 0 if valid, -1 if invalid or error.
int secp256k1_verify_signature(
    const uint8_t pubkey[33],
    const uint8_t message[32],
    const uint8_t signature[64]
);

#endif // NOBLE_SIGNING_H
