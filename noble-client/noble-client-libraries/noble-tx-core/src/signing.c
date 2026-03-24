// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Transaction signing using SHA-256 + secp256k1.

#include "signing.h"
#include "cbor.h"
#include "sha256.h"
#include "tx_builder.h"

#include <string.h>
#include "secp256k1.h"

// ── Signing message ─────────────────────────────────────────────────────

void compute_signing_message(
    const noble_tx_t *tx,
    uint32_t chain_id,
    uint8_t out[SHA256_DIGEST_SIZE]
) {
    noble_buf_t buf;
    noble_buf_init(&buf, 512);
    tx_encode_signing_payload(&buf, tx, chain_id);

    // Double-hash to match Rust k256's Signer::sign() which internally
    // hashes the message with SHA-256 before ECDSA. Since libsecp256k1's
    // secp256k1_ecdsa_sign treats its input as the final digest (no internal
    // hashing), we must pre-apply the second hash here.
    uint8_t intermediate[SHA256_DIGEST_SIZE];
    sha256(buf.data, buf.len, intermediate);
    sha256(intermediate, SHA256_DIGEST_SIZE, out);

    noble_buf_free(&buf);
}

// ── secp256k1 operations ────────────────────────────────────────────────

int secp256k1_sign_message(
    const uint8_t private_key[32],
    const uint8_t message[32],
    uint8_t signature_out[64]
) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;

    secp256k1_ecdsa_signature sig;
    int ok = secp256k1_ecdsa_sign(ctx, &sig, message, private_key, NULL, NULL);
    if (!ok) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Serialize to compact 64-byte format (r || s).
    secp256k1_ecdsa_signature_serialize_compact(ctx, signature_out, &sig);
    secp256k1_context_destroy(ctx);
    return 0;
}

int secp256k1_derive_pubkey(
    const uint8_t private_key[32],
    uint8_t pubkey_out[33]
) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, private_key)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &len, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    return 0;
}

// ── Transaction ID ──────────────────────────────────────────────────────

void compute_tx_id(
    const noble_tx_t *tx,
    uint32_t chain_id,
    uint8_t out[SHA256_DIGEST_SIZE]
) {
    noble_buf_t cbor;
    noble_buf_init(&cbor, 512);
    tx_encode_wire_full(&cbor, tx);

    // tx_id = double_sha256(chain_id_be || wire_cbor)
    // Matches noble-core: Transaction::compute_tx_id() in transaction.rs
    noble_buf_t preimage;
    noble_buf_init(&preimage, 4 + cbor.len);

    // chain_id as 4-byte big-endian
    uint8_t cid[4];
    cid[0] = (uint8_t)(chain_id >> 24);
    cid[1] = (uint8_t)(chain_id >> 16);
    cid[2] = (uint8_t)(chain_id >> 8);
    cid[3] = (uint8_t)(chain_id);
    noble_buf_append(&preimage, cid, 4);
    noble_buf_append(&preimage, cbor.data, cbor.len);

    double_sha256(preimage.data, preimage.len, out);

    noble_buf_free(&preimage);
    noble_buf_free(&cbor);
}

// ── Full sign-and-encode pipeline ───────────────────────────────────────

int sign_and_encode_tx(
    noble_tx_t *tx,
    const uint8_t private_key[32],
    uint32_t chain_id,
    noble_buf_t *tx_cbor_out,
    uint8_t tx_id_out[SHA256_DIGEST_SIZE]
) {
    // 1. Derive public key.
    uint8_t pubkey[33];
    if (secp256k1_derive_pubkey(private_key, pubkey) != 0)
        return -1;

    // 2. Set issuer_sig public key (signature still empty for signing message).
    tx->issuer_sig.scheme_id = 0x02; // SCHEME_SECP256K1
    memcpy(tx->issuer_sig.public_key, pubkey, 33);
    tx->issuer_sig.public_key_len = 33;
    memset(tx->issuer_sig.signature, 0, SIG_LEN);
    tx->issuer_sig.signature_len = 64;

    // 3. Compute signing message = SHA-256(signing_payload_cbor).
    uint8_t msg[SHA256_DIGEST_SIZE];
    compute_signing_message(tx, chain_id, msg);

    // 4. Sign.
    uint8_t sig[64];
    if (secp256k1_sign_message(private_key, msg, sig) != 0)
        return -1;

    // 5. Fill signature into issuer_sig.
    memcpy(tx->issuer_sig.signature, sig, 64);
    tx->issuer_sig.signature_len = 64;

    // 6. Encode full transaction.
    noble_buf_init(tx_cbor_out, 512);
    tx_encode_full(tx_cbor_out, tx);

    // 7. Compute tx_id.
    compute_tx_id(tx, chain_id, tx_id_out);

    return 0;
}

// ── Signature verification ────────────────────────────────────────────

int secp256k1_verify_signature(
    const uint8_t pubkey[33],
    const uint8_t message[32],
    const uint8_t signature[64]
) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return -1;

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey, 33)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    int valid = secp256k1_ecdsa_verify(ctx, &sig, message, &pk);
    secp256k1_context_destroy(ctx);
    return valid ? 0 : -1;
}
