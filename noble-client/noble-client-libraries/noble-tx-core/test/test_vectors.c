// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Frozen wire vector tests — must match noble-wire/src/vectors.rs exactly.
// If any test fails, the C encoder disagrees with the Rust encoder.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/cbor.h"
#include "../src/sha256.h"
#include "../src/hex.h"
#include "../src/tx_builder.h"

static int tests_run = 0;
static int tests_passed = 0;

static void assert_hex(const char *name, const noble_buf_t *buf, const char *expected) {
    tests_run++;
    char *actual = (char *)malloc(buf->len * 2 + 1);
    hex_encode(buf->data, buf->len, actual);
    if (strcmp(actual, expected) == 0) {
        tests_passed++;
        printf("  PASS: %s\n", name);
    } else {
        printf("  FAIL: %s\n", name);
        printf("    expected: %s\n", expected);
        printf("    actual:   %s\n", actual);
    }
    free(actual);
}

// ── Test: Hash256::ZERO as CBOR byte string ─────────────────────────────
// 32 zero bytes encoded as CBOR byte string: 0x5820 + 32 zeros
static void test_hash256_zero(void) {
    noble_buf_t buf;
    noble_buf_init(&buf, 64);
    uint8_t zeros[32] = {0};
    cbor_write_bytes(&buf, zeros, 32);
    assert_hex("Hash256::ZERO",
        &buf,
        "58200000000000000000000000000000000000000000000000000000000000000000");
    noble_buf_free(&buf);
}

// ── Test: OutPoint::COINBASE_PREVOUT as CBOR map ────────────────────────
// Map with 2 entries (sorted): {"txid": <32 zero bytes>, "vout": 0xFFFFFFFF}
static void test_outpoint_coinbase(void) {
    noble_buf_t buf;
    noble_buf_init(&buf, 128);
    cbor_write_map(&buf, 2);
    // "txid" < "vout" (alphabetical)
    cbor_write_text(&buf, "txid", 4);
    uint8_t zeros[32] = {0};
    cbor_write_bytes(&buf, zeros, 32);
    cbor_write_text(&buf, "vout", 4);
    cbor_write_uint(&buf, 0xFFFFFFFF);
    assert_hex("OutPoint::COINBASE",
        &buf,
        "a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff");
    noble_buf_free(&buf);
}

// ── Test: NoblePublicKey::Secp256k1 as CBOR byte string ─────────────────
// Wire format: [0x02, 0x02, 0x42*32] = 34 bytes total
// Encoded as CBOR byte string: 0x5822 + 34 bytes
static void test_pubkey_secp256k1(void) {
    noble_buf_t buf;
    noble_buf_init(&buf, 64);
    uint8_t wire[34];
    wire[0] = 0x02; // scheme_id
    wire[1] = 0x02; // compressed key prefix
    memset(wire + 2, 0x42, 32);
    cbor_write_bytes(&buf, wire, 34);
    assert_hex("NoblePublicKey::Secp256k1",
        &buf,
        "582202024242424242424242424242424242424242424242424242424242424242424242");
    noble_buf_free(&buf);
}

// ── Test: SignatureEnvelope as CBOR byte string ─────────────────────────
// Wire: [scheme_id=0x02, pubkey_len=0x21(33), pubkey(33), signature(64)] = 99 bytes
// Key: 0x02 + 0xBB*32, Sig: 0xCC*64
static void test_sig_envelope(void) {
    noble_buf_t buf;
    noble_buf_init(&buf, 128);
    uint8_t wire[99];
    wire[0] = 0x02;  // scheme_id
    wire[1] = 0x21;  // pubkey_len = 33
    wire[2] = 0x02;  // compressed key prefix
    memset(wire + 3, 0xBB, 32);  // pubkey x-coord
    memset(wire + 35, 0xCC, 64); // signature
    cbor_write_bytes(&buf, wire, 99);
    assert_hex("SignatureEnvelope",
        &buf,
        "5863022102bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    noble_buf_free(&buf);
}

// ── Test: SHA-256 known vector ──────────────────────────────────────────
static void test_sha256(void) {
    tests_run++;
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    uint8_t out[32];
    sha256(NULL, 0, out);
    char hex_out[65];
    hex_encode(out, 32, hex_out);
    const char *expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (strcmp(hex_out, expected) == 0) {
        tests_passed++;
        printf("  PASS: SHA-256(empty)\n");
    } else {
        printf("  FAIL: SHA-256(empty)\n");
        printf("    expected: %s\n", expected);
        printf("    actual:   %s\n", hex_out);
    }
}

static void test_sha256_abc(void) {
    tests_run++;
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    uint8_t out[32];
    sha256((const uint8_t *)"abc", 3, out);
    char hex_out[65];
    hex_encode(out, 32, hex_out);
    const char *expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (strcmp(hex_out, expected) == 0) {
        tests_passed++;
        printf("  PASS: SHA-256(\"abc\")\n");
    } else {
        printf("  FAIL: SHA-256(\"abc\")\n");
        printf("    expected: %s\n", expected);
        printf("    actual:   %s\n", hex_out);
    }
}

// ── Test: CBOR header edge cases ────────────────────────────────────────
static void test_cbor_uint_encoding(void) {
    // Test value 0: should be 0x00
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 0);
        tests_run++;
        if (buf.len == 1 && buf.data[0] == 0x00) { tests_passed++; printf("  PASS: uint(0)\n"); }
        else printf("  FAIL: uint(0)\n");
        noble_buf_free(&buf);
    }
    // Test value 23: should be 0x17
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 23);
        tests_run++;
        if (buf.len == 1 && buf.data[0] == 0x17) { tests_passed++; printf("  PASS: uint(23)\n"); }
        else printf("  FAIL: uint(23)\n");
        noble_buf_free(&buf);
    }
    // Test value 24: should be 0x18, 0x18
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 24);
        tests_run++;
        if (buf.len == 2 && buf.data[0] == 0x18 && buf.data[1] == 0x18) { tests_passed++; printf("  PASS: uint(24)\n"); }
        else printf("  FAIL: uint(24)\n");
        noble_buf_free(&buf);
    }
    // Test value 255: should be 0x18, 0xFF
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 255);
        tests_run++;
        if (buf.len == 2 && buf.data[0] == 0x18 && buf.data[1] == 0xFF) { tests_passed++; printf("  PASS: uint(255)\n"); }
        else printf("  FAIL: uint(255)\n");
        noble_buf_free(&buf);
    }
    // Test value 256: should be 0x19, 0x01, 0x00
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 256);
        tests_run++;
        if (buf.len == 3 && buf.data[0] == 0x19 && buf.data[1] == 0x01 && buf.data[2] == 0x00) { tests_passed++; printf("  PASS: uint(256)\n"); }
        else printf("  FAIL: uint(256)\n");
        noble_buf_free(&buf);
    }
    // Test value 0xFFFFFFFF: should be 0x1A + 4 bytes
    {
        noble_buf_t buf; noble_buf_init(&buf, 16);
        cbor_write_uint(&buf, 0xFFFFFFFF);
        tests_run++;
        if (buf.len == 5 && buf.data[0] == 0x1A) { tests_passed++; printf("  PASS: uint(0xFFFFFFFF)\n"); }
        else printf("  FAIL: uint(0xFFFFFFFF)\n");
        noble_buf_free(&buf);
    }
}

// ── Helper: build the test transaction matching noble-wire vectors ────────
static noble_tx_t make_coinbase_tx(void) {
    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.tx_type = 0x10; // TX_TYPE_COINBASE

    // Input: coinbase prevout (txid=zero, vout=0xFFFFFFFF)
    tx.input_count = 1;
    memset(tx.inputs[0].prev_output.txid, 0, HASH256_LEN);
    tx.inputs[0].prev_output.vout = 0xFFFFFFFF;

    // Output: 100_000_000 to test pubkey
    tx.output_count = 1;
    tx.outputs[0].value = 100000000; // 0x05F5E100
    tx.outputs[0].address.wire[0] = 0x02; // scheme_id
    tx.outputs[0].address.wire[1] = 0x02; // compressed prefix
    memset(tx.outputs[0].address.wire + 2, 0x42, 32);
    tx.outputs[0].address.wire_len = 34;

    // Checksum: zero
    memset(tx.checksum, 0, HASH256_LEN);

    // Timestamp: 1_700_000_000 (0x6553F100)
    tx.timestamp = 1700000000;

    // issuer_sig: scheme=0x02, pubkey=[0x02, 0x42*32], sig=[0x00*64]
    tx.issuer_sig.scheme_id = 0x02;
    tx.issuer_sig.public_key[0] = 0x02;
    memset(tx.issuer_sig.public_key + 1, 0x42, 32);
    tx.issuer_sig.public_key_len = 33;
    memset(tx.issuer_sig.signature, 0, SIG_LEN);
    tx.issuer_sig.signature_len = 64;

    tx.additional_sig_count = 0;
    tx.metadata_count = 0;
    tx.gateway_address_len = 0;
    tx.expires_at = 0;

    return tx;
}

// ── Test: Full coinbase transaction CBOR encoding ───────────────────────
static void test_coinbase_tx(void) {
    noble_tx_t tx = make_coinbase_tx();
    noble_buf_t buf;
    noble_buf_init(&buf, 512);
    tx_encode_full(&buf, &tx);
    assert_hex("Transaction (coinbase)",
        &buf,
        "a96f6164646974696f6e616c5f736967738068636865636b73756d5820000000000000000000000000000000000000000000000000000000000000000066696e7075747381a16b707265765f6f7574707574a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff6a6973737565725f7369675863022102424242424242424242424242424242424242424242424242424242424242424200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686d6574616461746180676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01");
    noble_buf_free(&buf);
}

// ── Test: TxSigningPayload CBOR encoding ────────────────────────────────
static void test_tx_signing_payload(void) {
    noble_tx_t tx = make_coinbase_tx();
    noble_buf_t buf;
    noble_buf_init(&buf, 512);
    tx_encode_signing_payload(&buf, &tx, 0x8C9FE969);
    assert_hex("TxSigningPayload",
        &buf,
        "a868636861696e5f69641a8c9fe96968636865636b73756d582000000000000000000000000000000000000000000000000000000000000000006f696e7075745f6f7574706f696e747381a264747869645820000000000000000000000000000000000000000000000000000000000000000064766f75741affffffff686d6574616461746180676f75747075747381a267616464726573735822020242424242424242424242424242424242424242424242424242424242424242426576616c75651a05f5e1006974696d657374616d701a6553f1006774785f74797065106776657273696f6e01");
    noble_buf_free(&buf);
}

int main(void) {
    printf("noble-tx-core frozen vector tests\n");
    printf("==================================\n");

    test_hash256_zero();
    test_outpoint_coinbase();
    test_pubkey_secp256k1();
    test_sig_envelope();
    test_sha256();
    test_sha256_abc();
    test_cbor_uint_encoding();
    test_coinbase_tx();
    test_tx_signing_payload();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
