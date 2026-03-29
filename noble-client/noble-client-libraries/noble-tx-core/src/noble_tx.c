// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Top-level API: JSON in, JSON out. Wraps CBOR encoder + signing + coin selection.

#include "../include/noble_tx.h"
#include "json.h"
#include "hex.h"
#include "sha256.h"
#include "signing.h"
#include "coin_select.h"
#include "tx_builder.h"
#include "aes_gcm.h"
#include "cbor_decode.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TX_TYPE_NOTARIZATION    0x00
#define TX_TYPE_TRANSFER        0x01
#define TX_TYPE_KEY_ROTATION    0x02
#define TX_TYPE_BADGE_PROPOSAL  0x03
#define TX_TYPE_BADGE_VOTE      0x04
#define TX_TYPE_BADGE_REVOCATION 0x05
#define TX_TYPE_LOCKED          0x06
#define TX_TYPE_UNLOCKING       0x07
#define TX_TYPE_COINBASE        0x10
#define TX_TYPE_FEE             0x11
#define TX_TYPE_DAO             0x12
#define PROTOCOL_VERSION        1

// ── Helpers ─────────────────────────────────────────────────────────────

static int parse_utxos_into_inputs(
    const json_value_t *utxos_arr,
    noble_tx_t *tx,
    noble_utxo_t *coin_utxos,
    size_t *coin_count
) {
    if (!utxos_arr || utxos_arr->type != JSON_ARRAY) return -1;
    size_t n = utxos_arr->array.count;
    if (n > MAX_INPUTS) n = MAX_INPUTS;

    for (size_t i = 0; i < n; i++) {
        const json_value_t *u = &utxos_arr->array.items[i];
        const char *txid_hex = json_get_string(u, "txid");
        uint32_t vout = json_get_uint32(u, "vout");
        uint64_t value = json_get_uint(u, "value");

        if (!txid_hex) return -1;

        // Parse txid hex → 32 bytes
        if (hex_decode(txid_hex, strlen(txid_hex), tx->inputs[i].prev_output.txid, HASH256_LEN) != HASH256_LEN)
            return -1;
        tx->inputs[i].prev_output.vout = vout;

        if (coin_utxos) {
            strncpy(coin_utxos[i].txid, txid_hex, 64);
            coin_utxos[i].txid[64] = '\0';
            coin_utxos[i].vout = vout;
            coin_utxos[i].value = value;
        }
    }
    tx->input_count = (uint8_t)n;
    if (coin_count) *coin_count = n;
    return 0;
}

static int parse_address_wire(const char *hex_str, noble_address_t *addr) {
    size_t hex_len = strlen(hex_str);
    int byte_len = hex_decode(hex_str, hex_len, addr->wire, 34);
    if (byte_len < 2) return -1;
    addr->wire_len = (uint8_t)byte_len;
    return 0;
}

static int parse_private_key(const char *hex_str, uint8_t key_out[32]) {
    size_t hex_len = strlen(hex_str);
    return hex_decode(hex_str, hex_len, key_out, 32) == 32 ? 0 : -1;
}

// ── noble_sign_transfer ─────────────────────────────────────────────────

char *noble_sign_transfer(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *recipient_hex = json_get_string(params, "recipient");
    uint64_t amount           = json_get_uint(params, "amount");
    uint64_t fee              = json_get_uint(params, "fee");
    const char *change_hex    = json_get_string(params, "change_address");
    const char *privkey_hex   = json_get_string(params, "private_key");
    uint32_t chain_id         = json_get_uint32(params, "chain_id");
    const json_value_t *utxos = json_get(params, "utxos");

    if (!recipient_hex || !change_hex || !privkey_hex || !utxos) {
        json_free(params);
        return json_emit_error("missing required field");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    // Build transaction.
    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_TRANSFER;

    // Parse inputs from UTXOs.
    if (parse_utxos_into_inputs(utxos, &tx, NULL, NULL) != 0) {
        json_free(params);
        return json_emit_error("invalid utxos");
    }

    // Output 0: recipient.
    noble_address_t recipient_addr;
    if (parse_address_wire(recipient_hex, &recipient_addr) != 0) {
        json_free(params);
        return json_emit_error("invalid recipient address");
    }
    tx.outputs[0].address = recipient_addr;
    tx.outputs[0].value = amount;
    tx.output_count = 1;

    // Parse change address.
    noble_address_t change_addr;
    if (parse_address_wire(change_hex, &change_addr) != 0) {
        json_free(params);
        return json_emit_error("invalid change_address");
    }

    // Compute total input value.
    uint64_t input_total = 0;
    for (uint8_t i = 0; i < tx.input_count; i++) {
        const json_value_t *u = &utxos->array.items[i];
        input_total += json_get_uint(u, "value");
    }

    tx.timestamp = json_get_uint(params, "timestamp");
    memset(tx.checksum, 0, HASH256_LEN);

    // Two-pass fee computation: build once to get exact CBOR size,
    // compute fee = size × fee_rate, then rebuild with correct fee.
    // The caller passes fee as either an absolute amount or a fee_rate.
    uint64_t fee_rate = json_get_uint(params, "fee_rate");
    uint64_t actual_fee = fee;

    if (fee_rate > 0) {
        // Pass 1: build with fee=0 to measure exact tx size.
        uint64_t change0 = input_total - amount;
        if (change0 > 0) {
            tx.outputs[1].address = change_addr;
            tx.outputs[1].value = change0;
            tx.output_count = 2;
        } else {
            tx.output_count = 1;
        }
        noble_buf_t probe;
        uint8_t dummy_id[HASH256_LEN];
        if (sign_and_encode_tx(&tx, private_key, chain_id, &probe, dummy_id) != 0) {
            json_free(params);
            return json_emit_error("signing failed (size probe)");
        }
        actual_fee = (uint64_t)probe.len * fee_rate;
        noble_buf_free(&probe);
    }

    // Final build with the correct fee.
    // Guard against unsigned underflow: if fee exceeds available funds,
    // return an error instead of wrapping to UINT64_MAX.
    if (actual_fee > input_total - amount) {
        json_free(params);
        return json_emit_error("insufficient funds for fee");
    }
    uint64_t change = input_total - amount - actual_fee;
    tx.outputs[0].value = amount;
    if (change > 0) {
        tx.outputs[1].address = change_addr;
        tx.outputs[1].value = change;
        tx.output_count = 2;
    } else {
        tx.output_count = 1;
    }

    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    // Emit result.
    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    char *result = fee_rate > 0
        ? json_emit_result_with_fee(tx_hex, tx_id_hex, actual_fee, cbor.len)
        : json_emit_result(tx_hex, tx_id_hex);

    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_sign_notarization ─────────────────────────────────────────────

char *noble_sign_notarization(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *checksum_hex  = json_get_string(params, "checksum");
    uint64_t fee              = json_get_uint(params, "fee");
    const char *change_hex    = json_get_string(params, "change_address");
    const char *privkey_hex   = json_get_string(params, "private_key");
    uint32_t chain_id         = json_get_uint32(params, "chain_id");
    const json_value_t *utxos = json_get(params, "utxos");
    const json_value_t *meta  = json_get(params, "metadata");

    if (!checksum_hex || !change_hex || !privkey_hex || !utxos) {
        json_free(params);
        return json_emit_error("missing required field");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_NOTARIZATION;

    // Checksum.
    if (hex_decode(checksum_hex, strlen(checksum_hex), tx.checksum, HASH256_LEN) != HASH256_LEN) {
        json_free(params);
        return json_emit_error("invalid checksum hex");
    }

    // Metadata.
    if (meta && meta->type == JSON_ARRAY) {
        size_t mc = meta->array.count;
        if (mc > MAX_METADATA) mc = MAX_METADATA;
        for (size_t i = 0; i < mc; i++) {
            const json_value_t *m = &meta->array.items[i];
            const char *k = json_get_string(m, "key");
            const char *v = json_get_string(m, "value");
            if (k && v) {
                strncpy(tx.metadata[i].key, k, 64);
                tx.metadata[i].key[64] = '\0';
                size_t vlen = strlen(v);
                if (vlen > 256) vlen = 256;
                memcpy(tx.metadata[i].value, v, vlen);
                tx.metadata[i].value_len = (uint16_t)vlen;
                tx.metadata_count++;
            }
        }
    }

    // Inputs.
    if (parse_utxos_into_inputs(utxos, &tx, NULL, NULL) != 0) {
        json_free(params);
        return json_emit_error("invalid utxos");
    }

    // Compute input total for change.
    uint64_t input_total = 0;
    for (uint8_t i = 0; i < tx.input_count; i++) {
        const json_value_t *u = &utxos->array.items[i];
        input_total += json_get_uint(u, "value");
    }

    noble_address_t change_addr;
    if (parse_address_wire(change_hex, &change_addr) != 0) {
        json_free(params);
        return json_emit_error("invalid change_address");
    }

    tx.timestamp = json_get_uint(params, "timestamp");

    // Two-pass fee computation (same as noble_sign_transfer):
    // When fee_rate is provided, build once to measure exact CBOR size,
    // then compute fee = size × fee_rate.
    uint64_t fee_rate = json_get_uint(params, "fee_rate");
    uint64_t actual_fee = fee;

    if (fee_rate > 0) {
        // Pass 1: build with fee=0 to measure exact tx size.
        uint64_t change0 = input_total;
        if (change0 > 0) {
            tx.outputs[0].address = change_addr;
            tx.outputs[0].value = change0;
            tx.output_count = 1;
        }
        noble_buf_t probe;
        uint8_t dummy_id[HASH256_LEN];
        if (sign_and_encode_tx(&tx, private_key, chain_id, &probe, dummy_id) != 0) {
            json_free(params);
            return json_emit_error("signing failed (size probe)");
        }
        actual_fee = (uint64_t)probe.len * fee_rate;
        noble_buf_free(&probe);
    }

    // Guard against unsigned underflow.
    if (actual_fee > input_total) {
        json_free(params);
        return json_emit_error("insufficient funds for fee");
    }

    // Output: change only (notarizations have no explicit recipient output).
    uint64_t change = input_total - actual_fee;
    if (change > 0) {
        tx.outputs[0].address = change_addr;
        tx.outputs[0].value = change;
        tx.output_count = 1;
    } else {
        tx.output_count = 0;
    }

    // Sign and encode.
    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    char *result = fee_rate > 0
        ? json_emit_result_with_fee(tx_hex, tx_id_hex, actual_fee, cbor.len)
        : json_emit_result(tx_hex, tx_id_hex);

    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_select_utxos ──────────────────────────────────────────────────

char *noble_select_utxos(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    uint64_t target = json_get_uint(params, "target");
    const json_value_t *utxos_arr = json_get(params, "utxos");

    if (!utxos_arr || utxos_arr->type != JSON_ARRAY || target == 0) {
        json_free(params);
        return json_emit_error("missing utxos or target");
    }

    size_t n = utxos_arr->array.count;
    if (n > MAX_UTXOS) n = MAX_UTXOS;

    noble_utxo_t utxos[MAX_UTXOS];
    for (size_t i = 0; i < n; i++) {
        const json_value_t *u = &utxos_arr->array.items[i];
        const char *txid = json_get_string(u, "txid");
        if (txid) { strncpy(utxos[i].txid, txid, 64); utxos[i].txid[64] = '\0'; }
        else utxos[i].txid[0] = '\0';
        utxos[i].vout = json_get_uint32(u, "vout");
        utxos[i].value = json_get_uint(u, "value");
    }

    noble_selection_t sel;
    if (coin_select(utxos, n, target, &sel) != 0) {
        json_free(params);
        return json_emit_error("insufficient funds");
    }

    // Build output JSON.
    size_t bufsize = 128 + sel.count * 128;
    char *out = (char *)malloc(bufsize);
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, bufsize - pos, "{\"selected\":[");
    for (size_t i = 0; i < sel.count; i++) {
        if (i > 0) out[pos++] = ',';
        pos += (size_t)snprintf(out + pos, bufsize - pos,
            "{\"txid\":\"%s\",\"vout\":%u,\"value\":%llu}",
            sel.selected[i].txid, sel.selected[i].vout,
            (unsigned long long)sel.selected[i].value);
    }
    pos += (size_t)snprintf(out + pos, bufsize - pos,
        "],\"total\":%llu,\"change\":%llu}",
        (unsigned long long)sel.total, (unsigned long long)sel.change);

    json_free(params);
    return out;
}

// ── noble_tx_encode ─────────────────────────────────────────────────────
// Encode a pre-built transaction to CBOR without signing.
// Input: JSON with all transaction fields including issuer_sig.
// Output: { "tx_hex": "...", "size": N }

char *noble_tx_encode(const char *tx_json) {
    json_value_t *params = json_parse(tx_json);
    if (!params) return json_emit_error("invalid JSON");

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = (uint16_t)json_get_uint(params, "version");
    tx.tx_type = (uint8_t)json_get_uint(params, "tx_type");
    tx.timestamp = json_get_uint(params, "timestamp");

    // Checksum
    const char *checksum_hex = json_get_string(params, "checksum");
    if (checksum_hex) {
        hex_decode(checksum_hex, strlen(checksum_hex), tx.checksum, HASH256_LEN);
    }

    // Inputs
    const json_value_t *inputs = json_get(params, "inputs");
    if (inputs && inputs->type == JSON_ARRAY) {
        size_t n = inputs->array.count;
        if (n > MAX_INPUTS) n = MAX_INPUTS;
        for (size_t i = 0; i < n; i++) {
            const json_value_t *inp = &inputs->array.items[i];
            const json_value_t *prev = json_get(inp, "prev_output");
            if (prev) {
                const char *txid_hex = json_get_string(prev, "txid");
                if (txid_hex) {
                    hex_decode(txid_hex, strlen(txid_hex),
                               tx.inputs[i].prev_output.txid, HASH256_LEN);
                }
                tx.inputs[i].prev_output.vout = json_get_uint32(prev, "vout");
            }
        }
        tx.input_count = (uint8_t)n;
    }

    // Outputs
    const json_value_t *outputs = json_get(params, "outputs");
    if (outputs && outputs->type == JSON_ARRAY) {
        size_t n = outputs->array.count;
        if (n > MAX_OUTPUTS) n = MAX_OUTPUTS;
        for (size_t i = 0; i < n; i++) {
            const json_value_t *out = &outputs->array.items[i];
            tx.outputs[i].value = json_get_uint(out, "value");
            const char *addr_hex = json_get_string(out, "address");
            if (addr_hex) {
                parse_address_wire(addr_hex, &tx.outputs[i].address);
            }
        }
        tx.output_count = (uint8_t)n;
    }

    // Issuer signature
    const json_value_t *sig = json_get(params, "issuer_sig");
    if (sig) {
        tx.issuer_sig.scheme_id = (uint8_t)json_get_uint(sig, "scheme_id");
        const char *pk_hex = json_get_string(sig, "public_key");
        if (pk_hex) {
            tx.issuer_sig.public_key_len = (uint8_t)hex_decode(
                pk_hex, strlen(pk_hex), tx.issuer_sig.public_key, PUBKEY_LEN);
        }
        const char *sig_hex = json_get_string(sig, "signature");
        if (sig_hex) {
            tx.issuer_sig.signature_len = (uint8_t)hex_decode(
                sig_hex, strlen(sig_hex), tx.issuer_sig.signature, SIG_LEN);
        }
    }

    // Metadata
    const json_value_t *meta = json_get(params, "metadata");
    if (meta && meta->type == JSON_ARRAY) {
        size_t mc = meta->array.count;
        if (mc > MAX_METADATA) mc = MAX_METADATA;
        for (size_t i = 0; i < mc; i++) {
            const json_value_t *m = &meta->array.items[i];
            const char *k = json_get_string(m, "key");
            const char *v = json_get_string(m, "value");
            if (k && v) {
                strncpy(tx.metadata[i].key, k, 64);
                tx.metadata[i].key[64] = '\0';
                size_t vlen = strlen(v);
                if (vlen > 256) vlen = 256;
                memcpy(tx.metadata[i].value, v, vlen);
                tx.metadata[i].value_len = (uint16_t)vlen;
                tx.metadata_count++;
            }
        }
    }

    // Additional signatures
    const json_value_t *add_sigs = json_get(params, "additional_sigs");
    if (add_sigs && add_sigs->type == JSON_ARRAY) {
        size_t sc = add_sigs->array.count;
        if (sc > MAX_SIGS) sc = MAX_SIGS;
        for (size_t i = 0; i < sc; i++) {
            const json_value_t *s = &add_sigs->array.items[i];
            tx.additional_sigs[i].scheme_id = (uint8_t)json_get_uint(s, "scheme_id");
            const char *pk = json_get_string(s, "public_key");
            if (pk) {
                tx.additional_sigs[i].public_key_len = (uint8_t)hex_decode(
                    pk, strlen(pk), tx.additional_sigs[i].public_key, PUBKEY_LEN);
            }
            const char *sg = json_get_string(s, "signature");
            if (sg) {
                tx.additional_sigs[i].signature_len = (uint8_t)hex_decode(
                    sg, strlen(sg), tx.additional_sigs[i].signature, SIG_LEN);
            }
            tx.additional_sig_count++;
        }
    }

    // Optional: gateway_address
    const char *gw_hex = json_get_string(params, "gateway_address");
    if (gw_hex && strlen(gw_hex) > 0) {
        tx.gateway_address_len = (uint8_t)hex_decode(
            gw_hex, strlen(gw_hex), tx.gateway_address, 34);
    }

    // Optional: expires_at
    uint64_t expires = json_get_uint(params, "expires_at");
    if (expires > 0) {
        tx.expires_at = expires;
    }

    // Encode to CBOR
    noble_buf_t cbor;
    noble_buf_init(&cbor, 512);
    tx_encode_full(&cbor, &tx);

    // Reject if serialized tx exceeds protocol limit.
    if (cbor.len > MAX_TX_SIZE) {
        noble_buf_free(&cbor);
        json_free(params);
        return json_emit_error("transaction exceeds MAX_TX_SIZE (8192 bytes)");
    }

    // Emit result
    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    size_t bufsize = 64 + cbor.len * 2;
    char *result = (char *)malloc(bufsize);
    snprintf(result, bufsize, "{\"tx_hex\":\"%s\",\"size\":%zu}", tx_hex, cbor.len);

    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── Shared helper: build a metadata-only tx (0x02–0x05, 0x12) ───────

static char *sign_metadata_tx(
    const char *params_json,
    uint8_t tx_type,
    const char *meta_keys[],
    const char *meta_values[],
    size_t meta_count
) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *privkey_hex   = json_get_string(params, "private_key");
    uint32_t chain_id         = json_get_uint32(params, "chain_id");

    // Governance types (0x02-0x05, 0x12) are zero-fee: no inputs, no outputs, no UTXOs.
    int is_governance = (tx_type >= 0x02 && tx_type <= 0x05) || tx_type == TX_TYPE_DAO;

    uint64_t fee              = 0;
    const char *change_hex    = NULL;
    const json_value_t *utxos = NULL;

    if (!is_governance) {
        fee        = json_get_uint(params, "fee");
        change_hex = json_get_string(params, "change_address");
        utxos      = json_get(params, "utxos");
        if (!change_hex || !utxos) {
            json_free(params);
            return json_emit_error("missing required field (change_address, utxos)");
        }
    }

    if (!privkey_hex) {
        json_free(params);
        return json_emit_error("missing private_key");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = tx_type;
    memset(tx.checksum, 0, HASH256_LEN);

    // Metadata
    for (size_t i = 0; i < meta_count && i < MAX_METADATA; i++) {
        strncpy(tx.metadata[i].key, meta_keys[i], 64);
        tx.metadata[i].key[64] = '\0';
        size_t vlen = strlen(meta_values[i]);
        if (vlen > 256) vlen = 256;
        memcpy(tx.metadata[i].value, meta_values[i], vlen);
        tx.metadata[i].value_len = (uint16_t)vlen;
        tx.metadata_count++;
    }

    tx.timestamp = json_get_uint(params, "timestamp");

    if (is_governance) {
        // Governance: zero inputs, zero outputs, zero fee.
        tx.input_count = 0;
        tx.output_count = 0;
    } else {
        // Non-governance: parse UTXOs, compute fee, add change output.
        if (parse_utxos_into_inputs(utxos, &tx, NULL, NULL) != 0) {
            json_free(params);
            return json_emit_error("invalid utxos");
        }

        uint64_t input_total = 0;
        for (uint8_t i = 0; i < tx.input_count; i++) {
            const json_value_t *u = &utxos->array.items[i];
            input_total += json_get_uint(u, "value");
        }

        noble_address_t change_addr;
        if (parse_address_wire(change_hex, &change_addr) != 0) {
            json_free(params);
            return json_emit_error("invalid change_address");
        }

        uint64_t fee_rate = json_get_uint(params, "fee_rate");
        uint64_t actual_fee = fee;

        if (fee_rate > 0) {
            uint64_t change0 = input_total;
            if (change0 > 0) {
                tx.outputs[0].address = change_addr;
                tx.outputs[0].value = change0;
                tx.output_count = 1;
            }
            noble_buf_t probe;
            uint8_t dummy_id[HASH256_LEN];
            if (sign_and_encode_tx(&tx, private_key, chain_id, &probe, dummy_id) != 0) {
                json_free(params);
                return json_emit_error("signing failed (size probe)");
            }
            actual_fee = (uint64_t)probe.len * fee_rate;
            noble_buf_free(&probe);
        }

        if (actual_fee > input_total) {
            json_free(params);
            return json_emit_error("insufficient funds for fee");
        }

        uint64_t change_val = input_total - actual_fee;
        if (change_val > 0) {
            tx.outputs[0].address = change_addr;
            tx.outputs[0].value = change_val;
            tx.output_count = 1;
        } else {
            tx.output_count = 0;
        }

        fee = actual_fee;
    }

    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    char *result = (!is_governance && json_get_uint(params, "fee_rate") > 0)
        ? json_emit_result_with_fee(tx_hex, tx_id_hex, fee, cbor.len)
        : json_emit_result(tx_hex, tx_id_hex);

    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_sign_key_rotation (0x02) ──────────────────────────────────

char *noble_sign_key_rotation(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *new_pubkey = json_get_string(params, "new_pubkey_hex");
    if (!new_pubkey) { json_free(params); return json_emit_error("missing new_pubkey_hex"); }
    const char *keys[] = { "new_pubkey" };
    const char *vals[] = { new_pubkey };
    char *result = sign_metadata_tx(params_json, TX_TYPE_KEY_ROTATION, keys, vals, 1);
    json_free(params);
    return result;
}

// ── noble_sign_badge_proposal (0x03) ────────────────────────────────

char *noble_sign_badge_proposal(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *target = json_get_string(params, "target_pubkey");
    const char *ptype  = json_get_string(params, "proposal_type");
    const char *reason = json_get_string(params, "reason");
    if (!target || !ptype) { json_free(params); return json_emit_error("missing target_pubkey or proposal_type"); }
    const char *keys[3] = { "proposal_type", "reason", "target_pubkey" };
    const char *vals[3] = { ptype, reason ? reason : "", target };
    char *result = sign_metadata_tx(params_json, TX_TYPE_BADGE_PROPOSAL, keys, vals, 3);
    json_free(params);
    return result;
}

// ── noble_sign_badge_vote (0x04) ────────────────────────────────────

char *noble_sign_badge_vote(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *phash = json_get_string(params, "proposal_hash");
    const char *vote  = json_get_string(params, "vote");
    if (!phash || !vote) { json_free(params); return json_emit_error("missing proposal_hash or vote"); }
    const char *keys[2] = { "proposal_hash", "vote" };
    const char *vals[2] = { phash, vote };
    char *result = sign_metadata_tx(params_json, TX_TYPE_BADGE_VOTE, keys, vals, 2);
    json_free(params);
    return result;
}

// ── noble_sign_badge_revocation (0x05) ──────────────────────────────

char *noble_sign_badge_revocation(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *badge_id = json_get_string(params, "badge_id");
    if (!badge_id) { json_free(params); return json_emit_error("missing badge_id"); }
    const char *keys[1] = { "badge_id" };
    const char *vals[1] = { badge_id };
    char *result = sign_metadata_tx(params_json, TX_TYPE_BADGE_REVOCATION, keys, vals, 1);
    json_free(params);
    return result;
}

// ── noble_sign_dao_create (0x12) ────────────────────────────────────

char *noble_sign_dao_create(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *question = json_get_string(params, "question");
    const char *expires  = json_get_string(params, "expires_cycles");
    if (!question) { json_free(params); return json_emit_error("missing question"); }
    const char *keys[3] = { "dao:action", "dao:question", "dao:expires_cycles" };
    const char *vals[3] = { "create", question, expires ? expires : "72" };
    char *result = sign_metadata_tx(params_json, TX_TYPE_DAO, keys, vals, 3);
    json_free(params);
    return result;
}

// ── noble_sign_dao_vote (0x12) ─────────────────────────────────────

char *noble_sign_dao_vote(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");
    const char *poll_id = json_get_string(params, "poll_id");
    const char *vote    = json_get_string(params, "vote");
    if (!poll_id || !vote) { json_free(params); return json_emit_error("missing poll_id or vote"); }
    const char *keys[3] = { "dao:action", "dao:poll_id", "dao:vote" };
    const char *vals[3] = { "vote", poll_id, vote };
    char *result = sign_metadata_tx(params_json, TX_TYPE_DAO, keys, vals, 3);
    json_free(params);
    return result;
}

// ── noble_build_coinbase (0x10) ─────────────────────────────────────
// Params: { private_key, chain_id, validator_address, subsidy_amount, timestamp }
// Builds block reward tx: 1 null input (COINBASE_PREVOUT) + 1 output to validator.

char *noble_build_coinbase(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *privkey_hex = json_get_string(params, "private_key");
    uint32_t chain_id       = json_get_uint32(params, "chain_id");
    const char *val_addr    = json_get_string(params, "validator_address");
    uint64_t subsidy        = json_get_uint(params, "subsidy_amount");
    uint64_t timestamp      = json_get_uint(params, "timestamp");

    if (!privkey_hex || !val_addr) {
        json_free(params);
        return json_emit_error("missing private_key or validator_address");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_COINBASE;
    memset(tx.checksum, 0, HASH256_LEN);
    tx.timestamp = timestamp;

    // Null input (COINBASE_PREVOUT): txid=zeros, vout=0xFFFFFFFF
    memset(tx.inputs[0].prev_output.txid, 0, HASH256_LEN);
    tx.inputs[0].prev_output.vout = 0xFFFFFFFF;
    tx.input_count = 1;

    // Output: subsidy to validator
    noble_address_t addr;
    if (parse_address_wire(val_addr, &addr) != 0) {
        json_free(params);
        return json_emit_error("invalid validator_address");
    }
    tx.outputs[0].address = addr;
    tx.outputs[0].value = subsidy;
    tx.output_count = 1;

    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);
    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);
    char *result = json_emit_result(tx_hex, tx_id_hex);
    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_build_fee_distribution (0x11) ─────────────────────────────
// Params: { private_key, chain_id, outputs: [{address, value}], timestamp }
// Builds fee distribution tx: 1 null input + N outputs (validator + gateways).

char *noble_build_fee_distribution(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *privkey_hex   = json_get_string(params, "private_key");
    uint32_t chain_id         = json_get_uint32(params, "chain_id");
    uint64_t timestamp        = json_get_uint(params, "timestamp");
    const json_value_t *outs  = json_get(params, "outputs");

    if (!privkey_hex || !outs) {
        json_free(params);
        return json_emit_error("missing private_key or outputs");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_FEE;
    memset(tx.checksum, 0, HASH256_LEN);
    tx.timestamp = timestamp;

    // Null input
    memset(tx.inputs[0].prev_output.txid, 0, HASH256_LEN);
    tx.inputs[0].prev_output.vout = 0xFFFFFFFF;
    tx.input_count = 1;

    // Parse outputs array
    tx.output_count = 0;
    for (size_t i = 0; i < outs->array.count && i < MAX_OUTPUTS; i++) {
        const json_value_t *out = &outs->array.items[i];
        const char *addr_hex = json_get_string(out, "address");
        uint64_t value = json_get_uint(out, "value");
        if (!addr_hex || value == 0) continue;
        noble_address_t addr;
        if (parse_address_wire(addr_hex, &addr) != 0) continue;
        tx.outputs[tx.output_count].address = addr;
        tx.outputs[tx.output_count].value = value;
        tx.output_count++;
    }

    if (tx.output_count == 0) {
        json_free(params);
        return json_emit_error("no valid outputs");
    }

    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);
    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);
    char *result = json_emit_result(tx_hex, tx_id_hex);
    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_sign_locked (0x06) ────────────────────────────────────────

char *noble_sign_locked(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *checksum_hex  = json_get_string(params, "checksum");
    const char *password_str  = json_get_string(params, "password");
    uint64_t fee              = json_get_uint(params, "fee");
    const char *change_hex    = json_get_string(params, "change_address");
    const char *privkey_hex   = json_get_string(params, "private_key");
    uint32_t chain_id         = json_get_uint32(params, "chain_id");
    const json_value_t *utxos = json_get(params, "utxos");
    const json_value_t *meta  = json_get(params, "metadata");

    if (!checksum_hex || !password_str || !change_hex || !privkey_hex || !utxos) {
        json_free(params);
        return json_emit_error("missing required field");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    // Generate random salt (16 bytes) and nonce (12 bytes)
    uint8_t salt[16], nonce[12];
    if (noble_random_bytes(salt, 16) != 0 || noble_random_bytes(nonce, 12) != 0) {
        json_free(params);
        return json_emit_error("random generation failed");
    }

    // Derive encryption key
    uint8_t enc_key[32];
    noble_derive_lock_key((const uint8_t *)password_str, strlen(password_str),
                          salt, 16, enc_key);

    // Encrypt the checksum (hex string → encrypted → hex encoded ciphertext)
    size_t cksum_len = strlen(checksum_hex);
    uint8_t *cksum_ct = (uint8_t *)malloc(cksum_len + 16);
    uint8_t cksum_tag[16];
    noble_aes_gcm_encrypt(enc_key, nonce,
                          (const uint8_t *)checksum_hex, cksum_len,
                          cksum_ct, cksum_tag);
    // Combine ciphertext + tag (matches Rust aes_gcm crate output format)
    uint8_t *cksum_combined = (uint8_t *)malloc(cksum_len + 16);
    memcpy(cksum_combined, cksum_ct, cksum_len);
    memcpy(cksum_combined + cksum_len, cksum_tag, 16);
    char *cksum_ct_hex = (char *)malloc((cksum_len + 16) * 2 + 1);
    hex_encode(cksum_combined, cksum_len + 16, cksum_ct_hex);
    free(cksum_ct);
    free(cksum_combined);

    // Hex-encode salt and nonce
    char salt_hex[33], nonce_hex[25];
    hex_encode(salt, 16, salt_hex);
    hex_encode(nonce, 12, nonce_hex);

    // Build the transaction
    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_LOCKED;
    memset(tx.checksum, 0, HASH256_LEN); // ZERO checksum on-chain

    // Collect user metadata keys+values, sort them alphabetically for encryption
    // (nonce counter alignment with Rust decryption)
    typedef struct { const char *key; const char *value; } kv_pair_t;
    kv_pair_t user_meta[MAX_METADATA];
    size_t user_meta_count = 0;

    if (meta && meta->type == JSON_ARRAY) {
        for (size_t i = 0; i < meta->array.count && user_meta_count < MAX_METADATA - 3; i++) {
            const json_value_t *m = &meta->array.items[i];
            const char *k = json_get_string(m, "key");
            const char *v = json_get_string(m, "value");
            if (k && v) {
                user_meta[user_meta_count].key = k;
                user_meta[user_meta_count].value = v;
                user_meta_count++;
            }
        }
    }

    // Sort user metadata by key (alphabetical) for nonce counter alignment
    for (size_t i = 0; i < user_meta_count; i++) {
        for (size_t j = i + 1; j < user_meta_count; j++) {
            if (strcmp(user_meta[i].key, user_meta[j].key) > 0) {
                kv_pair_t tmp = user_meta[i];
                user_meta[i] = user_meta[j];
                user_meta[j] = tmp;
            }
        }
    }

    // Validate: encrypted hex must fit in 256-byte metadata value buffer.
    // Max plaintext = (256 / 2) - 16 = 112 bytes.
    for (size_t i = 0; i < user_meta_count; i++) {
        if (strlen(user_meta[i].value) > 112) {
            free(cksum_ct_hex);
            memset(enc_key, 0, sizeof(enc_key));
            json_free(params);
            return json_emit_error("metadata value too long for locked encryption (max 112 bytes)");
        }
    }

    // Encrypt each user metadata value with per-field nonce
    // Nonce counter: 0 = checksum (base nonce), 1+ = metadata entries (alphabetical)
    char *encrypted_meta_hex[MAX_METADATA];
    for (size_t i = 0; i < user_meta_count; i++) {
        uint32_t counter = (uint32_t)(i + 1);
        uint8_t field_nonce[12];
        memcpy(field_nonce, nonce, 12);
        uint8_t counter_bytes[4];
        counter_bytes[0] = (uint8_t)(counter >> 24);
        counter_bytes[1] = (uint8_t)(counter >> 16);
        counter_bytes[2] = (uint8_t)(counter >> 8);
        counter_bytes[3] = (uint8_t)(counter);
        for (int b = 0; b < 4; b++) field_nonce[8 + b] ^= counter_bytes[b];

        size_t vlen = strlen(user_meta[i].value);
        uint8_t *ct = (uint8_t *)malloc(vlen + 16);
        uint8_t tag[16];
        noble_aes_gcm_encrypt(enc_key, field_nonce,
                              (const uint8_t *)user_meta[i].value, vlen,
                              ct, tag);
        // Combine ct + tag
        uint8_t *combined = (uint8_t *)malloc(vlen + 16);
        memcpy(combined, ct, vlen);
        memcpy(combined + vlen, tag, 16);
        encrypted_meta_hex[i] = (char *)malloc((vlen + 16) * 2 + 1);
        hex_encode(combined, vlen + 16, encrypted_meta_hex[i]);
        free(ct);
        free(combined);
    }

    // Build metadata array: locked:* entries + encrypted user entries
    size_t mi = 0;
    // locked:checksum
    strncpy(tx.metadata[mi].key, "locked:checksum", 64);
    size_t hlen = strlen(cksum_ct_hex);
    if (hlen > 256) hlen = 256;
    memcpy(tx.metadata[mi].value, cksum_ct_hex, hlen);
    tx.metadata[mi].value_len = (uint16_t)hlen;
    mi++;
    // locked:nonce
    strncpy(tx.metadata[mi].key, "locked:nonce", 64);
    memcpy(tx.metadata[mi].value, nonce_hex, strlen(nonce_hex));
    tx.metadata[mi].value_len = (uint16_t)strlen(nonce_hex);
    mi++;
    // locked:salt
    strncpy(tx.metadata[mi].key, "locked:salt", 64);
    memcpy(tx.metadata[mi].value, salt_hex, strlen(salt_hex));
    tx.metadata[mi].value_len = (uint16_t)strlen(salt_hex);
    mi++;
    // User metadata (encrypted values, original keys)
    for (size_t i = 0; i < user_meta_count; i++) {
        strncpy(tx.metadata[mi].key, user_meta[i].key, 64);
        tx.metadata[mi].key[64] = '\0';
        size_t evlen = strlen(encrypted_meta_hex[i]);
        if (evlen > 256) evlen = 256;
        memcpy(tx.metadata[mi].value, encrypted_meta_hex[i], evlen);
        tx.metadata[mi].value_len = (uint16_t)evlen;
        mi++;
    }
    tx.metadata_count = (uint8_t)mi;

    // Free encrypted hex strings
    free(cksum_ct_hex);
    for (size_t i = 0; i < user_meta_count; i++) free(encrypted_meta_hex[i]);

    // Inputs
    if (parse_utxos_into_inputs(utxos, &tx, NULL, NULL) != 0) {
        json_free(params);
        return json_emit_error("invalid utxos");
    }

    // Input total
    uint64_t input_total = 0;
    for (uint8_t i = 0; i < tx.input_count; i++) {
        const json_value_t *u = &utxos->array.items[i];
        input_total += json_get_uint(u, "value");
    }

    noble_address_t change_addr;
    if (parse_address_wire(change_hex, &change_addr) != 0) {
        json_free(params);
        return json_emit_error("invalid change_address");
    }

    tx.timestamp = json_get_uint(params, "timestamp");

    // Two-pass fee computation
    uint64_t fee_rate = json_get_uint(params, "fee_rate");
    uint64_t actual_fee = fee;
    if (fee_rate > 0) {
        if (input_total > 0) {
            tx.outputs[0].address = change_addr;
            tx.outputs[0].value = input_total;
            tx.output_count = 1;
        }
        noble_buf_t probe;
        uint8_t dummy_id[HASH256_LEN];
        if (sign_and_encode_tx(&tx, private_key, chain_id, &probe, dummy_id) != 0) {
            json_free(params);
            return json_emit_error("signing failed (size probe)");
        }
        actual_fee = (uint64_t)probe.len * fee_rate;
        noble_buf_free(&probe);
    }

    if (actual_fee > input_total) {
        json_free(params);
        return json_emit_error("insufficient funds for fee");
    }

    // Output: change
    uint64_t locked_change = input_total - actual_fee;
    if (locked_change > 0) {
        tx.outputs[0].address = change_addr;
        tx.outputs[0].value = locked_change;
        tx.output_count = 1;
    } else {
        tx.output_count = 0;
    }

    // Sign and encode
    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    char *result = fee_rate > 0
        ? json_emit_result_with_fee(tx_hex, tx_id_hex, actual_fee, cbor.len)
        : json_emit_result(tx_hex, tx_id_hex);

    memset(enc_key, 0, sizeof(enc_key));
    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── noble_sign_unlocking (0x07) ─────────────────────────────────────

char *noble_sign_unlocking(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *locked_txid  = json_get_string(params, "locked_tx_id");
    const char *password     = json_get_string(params, "password");
    const char *checksum_hex = json_get_string(params, "checksum");
    uint64_t fee             = json_get_uint(params, "fee");
    const char *change_hex   = json_get_string(params, "change_address");
    const char *privkey_hex  = json_get_string(params, "private_key");
    uint32_t chain_id        = json_get_uint32(params, "chain_id");
    const json_value_t *utxos = json_get(params, "utxos");

    if (!locked_txid || !password || !checksum_hex || !change_hex || !privkey_hex || !utxos) {
        json_free(params);
        return json_emit_error("missing required field");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = TX_TYPE_UNLOCKING;

    // Checksum = real document checksum (non-zero)
    if (hex_decode(checksum_hex, strlen(checksum_hex), tx.checksum, HASH256_LEN) != HASH256_LEN) {
        json_free(params);
        return json_emit_error("invalid checksum hex");
    }

    // Metadata: unlock:password, unlock:txid (alphabetical)
    size_t pwlen = strlen(password);
    if (pwlen > 256) {
        json_free(params);
        return json_emit_error("password too long (max 256 bytes)");
    }
    strncpy(tx.metadata[0].key, "unlock:password", 64);
    memcpy(tx.metadata[0].value, password, pwlen);
    tx.metadata[0].value_len = (uint16_t)pwlen;

    size_t txidlen = strlen(locked_txid);
    if (txidlen > 256) {
        json_free(params);
        return json_emit_error("locked_tx_id too long");
    }
    strncpy(tx.metadata[1].key, "unlock:txid", 64);
    memcpy(tx.metadata[1].value, locked_txid, txidlen);
    tx.metadata[1].value_len = (uint16_t)txidlen;
    tx.metadata_count = 2;

    // Inputs
    if (parse_utxos_into_inputs(utxos, &tx, NULL, NULL) != 0) {
        json_free(params);
        return json_emit_error("invalid utxos");
    }

    // Input total
    uint64_t input_total = 0;
    for (uint8_t i = 0; i < tx.input_count; i++) {
        const json_value_t *u = &utxos->array.items[i];
        input_total += json_get_uint(u, "value");
    }

    noble_address_t change_addr;
    if (parse_address_wire(change_hex, &change_addr) != 0) {
        json_free(params);
        return json_emit_error("invalid change_address");
    }

    tx.timestamp = json_get_uint(params, "timestamp");

    // Two-pass fee computation
    uint64_t fee_rate = json_get_uint(params, "fee_rate");
    uint64_t actual_fee = fee;
    if (fee_rate > 0) {
        if (input_total > 0) {
            tx.outputs[0].address = change_addr;
            tx.outputs[0].value = input_total;
            tx.output_count = 1;
        }
        noble_buf_t probe;
        uint8_t dummy_id[HASH256_LEN];
        if (sign_and_encode_tx(&tx, private_key, chain_id, &probe, dummy_id) != 0) {
            json_free(params);
            return json_emit_error("signing failed (size probe)");
        }
        actual_fee = (uint64_t)probe.len * fee_rate;
        noble_buf_free(&probe);
    }

    if (actual_fee > input_total) {
        json_free(params);
        return json_emit_error("insufficient funds for fee");
    }

    // Output: change
    uint64_t unlock_change = input_total - actual_fee;
    if (unlock_change > 0) {
        tx.outputs[0].address = change_addr;
        tx.outputs[0].value = unlock_change;
        tx.output_count = 1;
    } else {
        tx.output_count = 0;
    }

    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "signing failed");
        }
    }

    char *tx_hex = (char *)malloc(cbor.len * 2 + 1);
    hex_encode(cbor.data, cbor.len, tx_hex);

    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    char *result = fee_rate > 0
        ? json_emit_result_with_fee(tx_hex, tx_id_hex, actual_fee, cbor.len)
        : json_emit_result(tx_hex, tx_id_hex);

    free(tx_hex);
    noble_buf_free(&cbor);
    json_free(params);
    return result;
}

// ── CBOR decoder helpers ────────────────────────────────────────────

// Match a CBOR text key against a C string.
static int text_matches(const char *cbor_str, size_t cbor_len, const char *expected) {
    size_t elen = strlen(expected);
    return cbor_len == elen && memcmp(cbor_str, expected, elen) == 0;
}

// Decode a SignatureEnvelope from CBOR: map(3) { scheme_id, public_key, signature }
static int decode_sig_envelope(cbor_reader_t *r, noble_sig_envelope_t *sig) {
    size_t count;
    if (cbor_read_map(r, &count) != 0) return -1;
    for (size_t i = 0; i < count; i++) {
        const char *key; size_t klen;
        if (cbor_read_text(r, &key, &klen) != 0) return -1;
        if (text_matches(key, klen, "scheme_id")) {
            uint64_t v; if (cbor_read_uint(r, &v) != 0) return -1;
            sig->scheme_id = (uint8_t)v;
        } else if (text_matches(key, klen, "public_key")) {
            const uint8_t *data; size_t dlen;
            if (cbor_read_bytes(r, &data, &dlen) != 0) return -1;
            if (dlen > PUBKEY_LEN) dlen = PUBKEY_LEN;
            memcpy(sig->public_key, data, dlen);
            sig->public_key_len = (uint8_t)dlen;
        } else if (text_matches(key, klen, "signature")) {
            const uint8_t *data; size_t dlen;
            if (cbor_read_bytes(r, &data, &dlen) != 0) return -1;
            if (dlen > SIG_LEN) dlen = SIG_LEN;
            memcpy(sig->signature, data, dlen);
            sig->signature_len = (uint8_t)dlen;
        } else {
            if (cbor_skip(r) != 0) return -1;
        }
    }
    return 0;
}

// Decode a serde NobleAddress from CBOR:
//   {"Noble": {"Secp256k1": <bytes>}} → 0x02 + 33 bytes
//   {"BitcoinHash160": <bytes>}       → 0x80 + 20 bytes
//   {"BitcoinTaproot": <bytes>}       → 0x81 + 32 bytes
static int decode_address_serde(cbor_reader_t *r, noble_address_t *addr) {
    size_t count;
    if (cbor_read_map(r, &count) != 0 || count != 1) return -1;
    const char *key; size_t klen;
    if (cbor_read_text(r, &key, &klen) != 0) return -1;

    if (text_matches(key, klen, "Noble")) {
        // Nested map: {"Secp256k1": <bytes>}
        size_t inner;
        if (cbor_read_map(r, &inner) != 0 || inner != 1) return -1;
        const char *ikey; size_t iklen;
        if (cbor_read_text(r, &ikey, &iklen) != 0) return -1;
        const uint8_t *data; size_t dlen;
        if (cbor_read_bytes(r, &data, &dlen) != 0) return -1;
        addr->wire[0] = 0x02; // Secp256k1
        if (dlen > 33) dlen = 33;
        memcpy(&addr->wire[1], data, dlen);
        addr->wire_len = (uint8_t)(1 + dlen);
    } else if (text_matches(key, klen, "BitcoinHash160")) {
        const uint8_t *data; size_t dlen;
        if (cbor_read_bytes(r, &data, &dlen) != 0) return -1;
        addr->wire[0] = 0x80;
        if (dlen > 20) dlen = 20;
        memcpy(&addr->wire[1], data, dlen);
        addr->wire_len = (uint8_t)(1 + dlen);
    } else if (text_matches(key, klen, "BitcoinTaproot")) {
        const uint8_t *data; size_t dlen;
        if (cbor_read_bytes(r, &data, &dlen) != 0) return -1;
        addr->wire[0] = 0x81;
        if (dlen > 32) dlen = 32;
        memcpy(&addr->wire[1], data, dlen);
        addr->wire_len = (uint8_t)(1 + dlen);
    } else {
        return -1;
    }
    return 0;
}

// Decode a full transaction from CBOR bytes into noble_tx_t.
static int tx_from_cbor(const uint8_t *data, size_t len, noble_tx_t *tx) {
    cbor_reader_t r;
    cbor_reader_init(&r, data, len);
    memset(tx, 0, sizeof(noble_tx_t));

    size_t field_count;
    if (cbor_read_map(&r, &field_count) != 0) return -1;

    for (size_t f = 0; f < field_count; f++) {
        const char *key; size_t klen;
        if (cbor_read_text(&r, &key, &klen) != 0) return -1;

        if (text_matches(key, klen, "version")) {
            uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
            tx->version = (uint16_t)v;
        } else if (text_matches(key, klen, "tx_type")) {
            uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
            tx->tx_type = (uint8_t)v;
        } else if (text_matches(key, klen, "timestamp")) {
            uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
            tx->timestamp = v;
        } else if (text_matches(key, klen, "checksum")) {
            const uint8_t *d; size_t dlen;
            if (cbor_read_bytes(&r, &d, &dlen) != 0) return -1;
            if (dlen == HASH256_LEN) memcpy(tx->checksum, d, HASH256_LEN);
        } else if (text_matches(key, klen, "inputs")) {
            size_t arr_len;
            if (cbor_read_array(&r, &arr_len) != 0) return -1;
            if (arr_len > MAX_INPUTS) arr_len = MAX_INPUTS;
            for (size_t i = 0; i < arr_len; i++) {
                // TxIn: map(1) { "prev_output": OutPoint }
                size_t txin_fields;
                if (cbor_read_map(&r, &txin_fields) != 0) return -1;
                for (size_t j = 0; j < txin_fields; j++) {
                    const char *ik; size_t ikl;
                    if (cbor_read_text(&r, &ik, &ikl) != 0) return -1;
                    if (text_matches(ik, ikl, "prev_output")) {
                        // OutPoint: map(2) { "txid": bytes, "vout": uint }
                        size_t op_fields;
                        if (cbor_read_map(&r, &op_fields) != 0) return -1;
                        for (size_t k = 0; k < op_fields; k++) {
                            const char *ok; size_t okl;
                            if (cbor_read_text(&r, &ok, &okl) != 0) return -1;
                            if (text_matches(ok, okl, "txid")) {
                                const uint8_t *td; size_t tl;
                                if (cbor_read_bytes(&r, &td, &tl) != 0) return -1;
                                if (tl == HASH256_LEN) memcpy(tx->inputs[i].prev_output.txid, td, HASH256_LEN);
                            } else if (text_matches(ok, okl, "vout")) {
                                uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
                                tx->inputs[i].prev_output.vout = (uint32_t)v;
                            } else { cbor_skip(&r); }
                        }
                    } else { cbor_skip(&r); }
                }
            }
            tx->input_count = (uint8_t)arr_len;
        } else if (text_matches(key, klen, "outputs")) {
            size_t arr_len;
            if (cbor_read_array(&r, &arr_len) != 0) return -1;
            if (arr_len > MAX_OUTPUTS) arr_len = MAX_OUTPUTS;
            for (size_t i = 0; i < arr_len; i++) {
                // TxOut: map(2) { "address": serde_enum, "value": uint }
                size_t txo_fields;
                if (cbor_read_map(&r, &txo_fields) != 0) return -1;
                for (size_t j = 0; j < txo_fields; j++) {
                    const char *ok; size_t okl;
                    if (cbor_read_text(&r, &ok, &okl) != 0) return -1;
                    if (text_matches(ok, okl, "address")) {
                        decode_address_serde(&r, &tx->outputs[i].address);
                    } else if (text_matches(ok, okl, "value")) {
                        uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
                        tx->outputs[i].value = v;
                    } else { cbor_skip(&r); }
                }
            }
            tx->output_count = (uint8_t)arr_len;
        } else if (text_matches(key, klen, "issuer_sig")) {
            if (decode_sig_envelope(&r, &tx->issuer_sig) != 0) return -1;
        } else if (text_matches(key, klen, "additional_sigs")) {
            size_t arr_len;
            if (cbor_read_array(&r, &arr_len) != 0) return -1;
            if (arr_len > MAX_SIGS) arr_len = MAX_SIGS;
            for (size_t i = 0; i < arr_len; i++) {
                if (decode_sig_envelope(&r, &tx->additional_sigs[i]) != 0) return -1;
            }
            tx->additional_sig_count = (uint8_t)arr_len;
        } else if (text_matches(key, klen, "metadata")) {
            size_t arr_len;
            if (cbor_read_array(&r, &arr_len) != 0) return -1;
            if (arr_len > MAX_METADATA) arr_len = MAX_METADATA;
            for (size_t i = 0; i < arr_len; i++) {
                // MetadataEntry: map(2) { "key": text, "value": bytes }
                size_t me_fields;
                if (cbor_read_map(&r, &me_fields) != 0) return -1;
                for (size_t j = 0; j < me_fields; j++) {
                    const char *mk; size_t mkl;
                    if (cbor_read_text(&r, &mk, &mkl) != 0) return -1;
                    if (text_matches(mk, mkl, "key")) {
                        const char *s; size_t sl;
                        if (cbor_read_text(&r, &s, &sl) != 0) return -1;
                        if (sl > 64) sl = 64;
                        memcpy(tx->metadata[i].key, s, sl);
                        tx->metadata[i].key[sl] = '\0';
                    } else if (text_matches(mk, mkl, "value")) {
                        const uint8_t *d; size_t dl;
                        if (cbor_read_bytes(&r, &d, &dl) != 0) return -1;
                        if (dl > 256) dl = 256;
                        memcpy(tx->metadata[i].value, d, dl);
                        tx->metadata[i].value_len = (uint16_t)dl;
                    } else { cbor_skip(&r); }
                }
            }
            tx->metadata_count = (uint8_t)arr_len;
        } else if (text_matches(key, klen, "gateway_address")) {
            const uint8_t *d; size_t dl;
            if (cbor_read_bytes(&r, &d, &dl) != 0) return -1;
            if (dl > 34) dl = 34;
            memcpy(tx->gateway_address, d, dl);
            tx->gateway_address_len = (uint8_t)dl;
        } else if (text_matches(key, klen, "expires_at")) {
            uint64_t v; if (cbor_read_uint(&r, &v) != 0) return -1;
            tx->expires_at = v;
        } else {
            // Skip unknown fields (forward compat)
            if (cbor_skip(&r) != 0) return -1;
        }
    }
    return 0;
}

// Serialize a decoded noble_tx_t to JSON string.
static char *tx_to_json_string(const noble_tx_t *tx) {
    // Estimate buffer size
    size_t bufsize = 4096 + tx->input_count * 128 + tx->output_count * 128
                   + tx->metadata_count * 600 + tx->additional_sig_count * 256;
    char *out = (char *)malloc(bufsize);
    if (!out) return json_emit_error("allocation failed");
    size_t pos = 0;

    pos += (size_t)snprintf(out + pos, bufsize - pos,
        "{\"version\":%u,\"tx_type\":%u,\"timestamp\":%llu,\"checksum\":\"",
        tx->version, tx->tx_type, (unsigned long long)tx->timestamp);

    char cksum_hex[65];
    hex_encode(tx->checksum, HASH256_LEN, cksum_hex);
    pos += (size_t)snprintf(out + pos, bufsize - pos, "%s\"", cksum_hex);

    // Inputs
    pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"inputs\":[");
    for (uint8_t i = 0; i < tx->input_count; i++) {
        if (i > 0) out[pos++] = ',';
        char txid_hex[65];
        hex_encode(tx->inputs[i].prev_output.txid, HASH256_LEN, txid_hex);
        pos += (size_t)snprintf(out + pos, bufsize - pos,
            "{\"prev_output\":{\"txid\":\"%s\",\"vout\":%u}}",
            txid_hex, tx->inputs[i].prev_output.vout);
    }
    out[pos++] = ']';

    // Outputs
    pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"outputs\":[");
    for (uint8_t i = 0; i < tx->output_count; i++) {
        if (i > 0) out[pos++] = ',';
        char addr_hex[69];
        hex_encode(tx->outputs[i].address.wire, tx->outputs[i].address.wire_len, addr_hex);
        pos += (size_t)snprintf(out + pos, bufsize - pos,
            "{\"address\":\"%s\",\"value\":%llu}",
            addr_hex, (unsigned long long)tx->outputs[i].value);
    }
    out[pos++] = ']';

    // Issuer sig
    {
        char pk_hex[67], sig_hex[129];
        hex_encode(tx->issuer_sig.public_key, tx->issuer_sig.public_key_len, pk_hex);
        hex_encode(tx->issuer_sig.signature, tx->issuer_sig.signature_len, sig_hex);
        pos += (size_t)snprintf(out + pos, bufsize - pos,
            ",\"issuer_sig\":{\"scheme_id\":%u,\"public_key\":\"%s\",\"signature\":\"%s\"}",
            tx->issuer_sig.scheme_id, pk_hex, sig_hex);
    }

    // Additional sigs
    pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"additional_sigs\":[");
    for (uint8_t i = 0; i < tx->additional_sig_count; i++) {
        if (i > 0) out[pos++] = ',';
        char pk_hex[67], sig_hex[129];
        hex_encode(tx->additional_sigs[i].public_key, tx->additional_sigs[i].public_key_len, pk_hex);
        hex_encode(tx->additional_sigs[i].signature, tx->additional_sigs[i].signature_len, sig_hex);
        pos += (size_t)snprintf(out + pos, bufsize - pos,
            "{\"scheme_id\":%u,\"public_key\":\"%s\",\"signature\":\"%s\"}",
            tx->additional_sigs[i].scheme_id, pk_hex, sig_hex);
    }
    out[pos++] = ']';

    // Metadata
    pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"metadata\":[");
    for (uint8_t i = 0; i < tx->metadata_count; i++) {
        if (i > 0) out[pos++] = ',';
        // Try UTF-8 first, fall back to hex
        int is_utf8 = 1;
        for (uint16_t j = 0; j < tx->metadata[i].value_len; j++) {
            if (tx->metadata[i].value[j] == 0 || tx->metadata[i].value[j] == '"' || tx->metadata[i].value[j] == '\\') {
                is_utf8 = 0; break;
            }
        }
        if (is_utf8) {
            pos += (size_t)snprintf(out + pos, bufsize - pos, "{\"key\":\"%s\",\"value\":\"", tx->metadata[i].key);
            memcpy(out + pos, tx->metadata[i].value, tx->metadata[i].value_len);
            pos += tx->metadata[i].value_len;
            pos += (size_t)snprintf(out + pos, bufsize - pos, "\"}");
        } else {
            char *val_hex = (char *)malloc(tx->metadata[i].value_len * 2 + 1);
            hex_encode(tx->metadata[i].value, tx->metadata[i].value_len, val_hex);
            pos += (size_t)snprintf(out + pos, bufsize - pos,
                "{\"key\":\"%s\",\"value\":\"%s\",\"encoding\":\"hex\"}", tx->metadata[i].key, val_hex);
            free(val_hex);
        }
    }
    out[pos++] = ']';

    // Optional fields
    if (tx->gateway_address_len > 0) {
        char gw_hex[69];
        hex_encode(tx->gateway_address, tx->gateway_address_len, gw_hex);
        pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"gateway_address\":\"%s\"", gw_hex);
    }
    if (tx->expires_at > 0) {
        pos += (size_t)snprintf(out + pos, bufsize - pos, ",\"expires_at\":%llu", (unsigned long long)tx->expires_at);
    }

    out[pos++] = '}';
    out[pos] = '\0';
    return out;
}

// ── noble_tx_decode ─────────────────────────────────────────────────

char *noble_tx_decode(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *tx_hex_str = json_get_string(params, "tx_hex");
    if (!tx_hex_str) {
        json_free(params);
        return json_emit_error("missing tx_hex");
    }

    size_t hex_len = strlen(tx_hex_str);
    size_t byte_len = hex_len / 2;
    uint8_t *cbor_data = (uint8_t *)malloc(byte_len);
    if (hex_decode(tx_hex_str, hex_len, cbor_data, byte_len) != (int)byte_len) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("invalid tx_hex");
    }

    noble_tx_t tx;
    if (tx_from_cbor(cbor_data, byte_len, &tx) != 0) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("CBOR decode failed");
    }

    char *result = tx_to_json_string(&tx);

    free(cbor_data);
    json_free(params);
    return result;
}

// ── noble_tx_decode_locked ──────────────────────────────────────────

char *noble_tx_decode_locked(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *tx_hex_str  = json_get_string(params, "tx_hex");
    const char *password    = json_get_string(params, "password");
    if (!tx_hex_str || !password) {
        json_free(params);
        return json_emit_error("missing tx_hex or password");
    }

    size_t hex_len = strlen(tx_hex_str);
    size_t byte_len = hex_len / 2;
    uint8_t *cbor_data = (uint8_t *)malloc(byte_len);
    if (hex_decode(tx_hex_str, hex_len, cbor_data, byte_len) != (int)byte_len) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("invalid tx_hex");
    }

    noble_tx_t tx;
    if (tx_from_cbor(cbor_data, byte_len, &tx) != 0) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("CBOR decode failed");
    }
    free(cbor_data);

    if (tx.tx_type != TX_TYPE_LOCKED) {
        json_free(params);
        return json_emit_error("not a locked transaction");
    }

    // Extract locked:salt, locked:nonce, locked:checksum
    const char *salt_hex_str = NULL, *nonce_hex_str = NULL, *cksum_ct_hex = NULL;
    for (uint8_t i = 0; i < tx.metadata_count; i++) {
        if (strcmp(tx.metadata[i].key, "locked:salt") == 0)
            salt_hex_str = (const char *)tx.metadata[i].value;
        else if (strcmp(tx.metadata[i].key, "locked:nonce") == 0)
            nonce_hex_str = (const char *)tx.metadata[i].value;
        else if (strcmp(tx.metadata[i].key, "locked:checksum") == 0)
            cksum_ct_hex = (const char *)tx.metadata[i].value;
    }

    if (!salt_hex_str || !nonce_hex_str || !cksum_ct_hex) {
        json_free(params);
        return json_emit_error("missing locked:* metadata");
    }

    // Decode salt and nonce
    uint8_t salt[16], nonce_bytes[12];
    if (hex_decode(salt_hex_str, strlen(salt_hex_str), salt, 16) != 16) {
        json_free(params); return json_emit_error("invalid locked:salt");
    }
    if (hex_decode(nonce_hex_str, strlen(nonce_hex_str), nonce_bytes, 12) != 12) {
        json_free(params); return json_emit_error("invalid locked:nonce");
    }

    // Derive key
    uint8_t enc_key[32];
    noble_derive_lock_key((const uint8_t *)password, strlen(password), salt, 16, enc_key);

    // Decrypt checksum
    size_t cksum_ct_hex_len = strlen(cksum_ct_hex);
    size_t cksum_ct_bytes = cksum_ct_hex_len / 2;
    uint8_t *cksum_ct = (uint8_t *)malloc(cksum_ct_bytes);
    hex_decode(cksum_ct_hex, cksum_ct_hex_len, cksum_ct, cksum_ct_bytes);

    if (cksum_ct_bytes < 16) {
        free(cksum_ct); json_free(params);
        return json_emit_error("checksum ciphertext too short");
    }
    size_t cksum_pt_len = cksum_ct_bytes - 16;
    uint8_t *cksum_pt = (uint8_t *)malloc(cksum_pt_len + 1);
    if (noble_aes_gcm_decrypt(enc_key, nonce_bytes,
                               cksum_ct, cksum_pt_len,
                               cksum_ct + cksum_pt_len, cksum_pt) != 0) {
        free(cksum_ct); free(cksum_pt); json_free(params);
        return json_emit_error("decryption failed (wrong password?)");
    }
    cksum_pt[cksum_pt_len] = '\0';
    free(cksum_ct);

    // Build base JSON
    char *base_json = tx_to_json_string(&tx);

    // Append decrypted fields
    size_t base_len = strlen(base_json);
    // Replace closing } with additional fields
    size_t extra_size = 512 + cksum_pt_len + tx.metadata_count * 600;
    char *result = (char *)malloc(base_len + extra_size);
    memcpy(result, base_json, base_len - 1); // skip closing }
    size_t pos = base_len - 1;

    pos += (size_t)snprintf(result + pos, base_len + extra_size - pos,
        ",\"decrypted_checksum\":\"%s\"", (char *)cksum_pt);
    free(cksum_pt);

    // Decrypt user metadata
    pos += (size_t)snprintf(result + pos, base_len + extra_size - pos,
        ",\"decrypted_metadata\":[");

    // Collect and sort user metadata by key (same order as encryption)
    typedef struct { uint8_t idx; } sorted_idx_t;
    sorted_idx_t sorted[MAX_METADATA];
    size_t user_count = 0;
    for (uint8_t i = 0; i < tx.metadata_count; i++) {
        if (strncmp(tx.metadata[i].key, "locked:", 7) != 0) {
            sorted[user_count++].idx = i;
        }
    }
    // Sort by key
    for (size_t i = 0; i < user_count; i++) {
        for (size_t j = i + 1; j < user_count; j++) {
            if (strcmp(tx.metadata[sorted[i].idx].key, tx.metadata[sorted[j].idx].key) > 0) {
                sorted_idx_t tmp = sorted[i]; sorted[i] = sorted[j]; sorted[j] = tmp;
            }
        }
    }

    int first = 1;
    uint32_t nonce_counter = 1;
    for (size_t i = 0; i < user_count; i++) {
        uint8_t mi2 = sorted[i].idx;
        // Compute field nonce
        uint8_t field_nonce[12];
        memcpy(field_nonce, nonce_bytes, 12);
        uint8_t counter_bytes[4];
        counter_bytes[0] = (uint8_t)(nonce_counter >> 24);
        counter_bytes[1] = (uint8_t)(nonce_counter >> 16);
        counter_bytes[2] = (uint8_t)(nonce_counter >> 8);
        counter_bytes[3] = (uint8_t)(nonce_counter);
        for (int b = 0; b < 4; b++) field_nonce[8 + b] ^= counter_bytes[b];
        nonce_counter++;

        // Decode hex ciphertext from metadata value
        size_t val_hex_len = tx.metadata[mi2].value_len;
        size_t val_ct_len = val_hex_len / 2;
        uint8_t *val_ct = (uint8_t *)malloc(val_ct_len);
        hex_decode((const char *)tx.metadata[mi2].value, val_hex_len, val_ct, val_ct_len);

        if (val_ct_len >= 16) {
            size_t pt_len = val_ct_len - 16;
            uint8_t *pt = (uint8_t *)malloc(pt_len + 1);
            if (noble_aes_gcm_decrypt(enc_key, field_nonce,
                                       val_ct, pt_len,
                                       val_ct + pt_len, pt) == 0) {
                pt[pt_len] = '\0';
                if (!first) result[pos++] = ',';
                first = 0;
                pos += (size_t)snprintf(result + pos, base_len + extra_size - pos,
                    "{\"key\":\"%s\",\"value\":\"%s\"}", tx.metadata[mi2].key, (char *)pt);
            }
            free(pt);
        }
        free(val_ct);
    }

    pos += (size_t)snprintf(result + pos, base_len + extra_size - pos, "]}");
    result[pos] = '\0';

    memset(enc_key, 0, sizeof(enc_key));
    free(base_json);
    json_free(params);
    return result;
}

// ── noble_verify_tx ─────────────────────────────────────────────────

char *noble_verify_tx(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *tx_hex_str = json_get_string(params, "tx_hex");
    uint32_t chain_id      = json_get_uint32(params, "chain_id");
    if (!tx_hex_str) {
        json_free(params);
        return json_emit_error("missing tx_hex");
    }

    size_t hex_len = strlen(tx_hex_str);
    size_t byte_len = hex_len / 2;
    uint8_t *cbor_data = (uint8_t *)malloc(byte_len);
    if (hex_decode(tx_hex_str, hex_len, cbor_data, byte_len) != (int)byte_len) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("invalid tx_hex");
    }

    noble_tx_t tx;
    if (tx_from_cbor(cbor_data, byte_len, &tx) != 0) {
        free(cbor_data);
        json_free(params);
        return json_emit_error("CBOR decode failed");
    }

    // Save the real signature, then zero it for signing message computation
    uint8_t saved_sig[SIG_LEN];
    memcpy(saved_sig, tx.issuer_sig.signature, tx.issuer_sig.signature_len);
    memset(tx.issuer_sig.signature, 0, SIG_LEN);
    // Keep signature_len at 64 (matches signing: empty sig is 64 zero bytes)

    // Compute signing message
    uint8_t signing_msg[SHA256_DIGEST_SIZE];
    compute_signing_message(&tx, chain_id, signing_msg);

    // Verify
    int valid = secp256k1_verify_signature(
        tx.issuer_sig.public_key,
        signing_msg,
        saved_sig
    );

    // Compute tx_id from the ORIGINAL tx (with real signature)
    memcpy(tx.issuer_sig.signature, saved_sig, tx.issuer_sig.signature_len);
    uint8_t tx_id[HASH256_LEN];
    compute_tx_id(&tx, chain_id, tx_id);

    // Build result
    char signer_hex[67];
    hex_encode(tx.issuer_sig.public_key, tx.issuer_sig.public_key_len, signer_hex);
    char tx_id_hex[65];
    hex_encode(tx_id, HASH256_LEN, tx_id_hex);

    size_t rsize = 256;
    char *result = (char *)malloc(rsize);
    snprintf(result, rsize,
        "{\"valid\":%s,\"signer\":\"%s\",\"tx_id\":\"%s\"}",
        valid == 0 ? "true" : "false",
        signer_hex, tx_id_hex);

    free(cbor_data);
    json_free(params);
    return result;
}

// ── noble_estimate_tx_size ───────────────────────────────────────────

char *noble_estimate_tx_size(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *tx_type_str = json_get_string(params, "tx_type");
    if (!tx_type_str) { json_free(params); return json_emit_error("missing tx_type"); }

    // Determine tx_type code
    uint8_t tx_type = 0xFF;
    if (strcmp(tx_type_str, "notarization") == 0) tx_type = TX_TYPE_NOTARIZATION;
    else if (strcmp(tx_type_str, "transfer") == 0) tx_type = TX_TYPE_TRANSFER;
    else if (strcmp(tx_type_str, "locked") == 0) tx_type = TX_TYPE_LOCKED;
    else if (strcmp(tx_type_str, "unlocking") == 0) tx_type = TX_TYPE_UNLOCKING;
    else if (strcmp(tx_type_str, "key_rotation") == 0) tx_type = TX_TYPE_KEY_ROTATION;
    else if (strcmp(tx_type_str, "badge_proposal") == 0) tx_type = TX_TYPE_BADGE_PROPOSAL;
    else if (strcmp(tx_type_str, "badge_vote") == 0) tx_type = TX_TYPE_BADGE_VOTE;
    else if (strcmp(tx_type_str, "badge_revocation") == 0) tx_type = TX_TYPE_BADGE_REVOCATION;
    else if (strcmp(tx_type_str, "dao") == 0) tx_type = TX_TYPE_DAO;
    else if (strcmp(tx_type_str, "coinbase") == 0) tx_type = TX_TYPE_COINBASE;
    else if (strcmp(tx_type_str, "fee_distribution") == 0) tx_type = TX_TYPE_FEE;
    if (tx_type == 0xFF) { json_free(params); return json_emit_error("unknown tx_type"); }

    const char *change_hex  = json_get_string(params, "change_address");
    const char *privkey_hex = json_get_string(params, "private_key");
    uint32_t chain_id       = json_get_uint32(params, "chain_id");

    if (!change_hex || !privkey_hex) {
        json_free(params);
        return json_emit_error("missing change_address or private_key");
    }

    uint8_t private_key[32];
    if (parse_private_key(privkey_hex, private_key) != 0) {
        json_free(params);
        return json_emit_error("invalid private_key hex");
    }

    noble_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = PROTOCOL_VERSION;
    tx.tx_type = tx_type;

    // Checksum
    const char *checksum_hex = json_get_string(params, "checksum");
    if (checksum_hex) {
        hex_decode(checksum_hex, strlen(checksum_hex), tx.checksum, HASH256_LEN);
    }

    // Metadata
    const json_value_t *meta = json_get(params, "metadata");
    if (meta && meta->type == JSON_ARRAY) {
        size_t mc = meta->array.count;
        if (mc > MAX_METADATA) mc = MAX_METADATA;
        for (size_t i = 0; i < mc; i++) {
            const json_value_t *m = &meta->array.items[i];
            const char *k = json_get_string(m, "key");
            const char *v = json_get_string(m, "value");
            if (k && v) {
                strncpy(tx.metadata[tx.metadata_count].key, k, 64);
                tx.metadata[tx.metadata_count].key[64] = '\0';
                size_t vlen = strlen(v);
                if (vlen > 256) vlen = 256;
                memcpy(tx.metadata[tx.metadata_count].value, v, vlen);
                tx.metadata[tx.metadata_count].value_len = (uint16_t)vlen;
                tx.metadata_count++;
            }
        }
    }

    // Inputs — use provided UTXOs or simulate 1 input
    const json_value_t *utxos = json_get(params, "utxos");
    if (utxos && utxos->type == JSON_ARRAY && utxos->array.count > 0) {
        parse_utxos_into_inputs(utxos, &tx, NULL, NULL);
    } else {
        // Simulate 1 input for size estimation
        memset(tx.inputs[0].prev_output.txid, 0xAA, HASH256_LEN);
        tx.inputs[0].prev_output.vout = 0;
        tx.input_count = 1;
    }

    // Output — simulate 1 change output
    noble_address_t change_addr;
    if (parse_address_wire(change_hex, &change_addr) == 0) {
        tx.outputs[0].address = change_addr;
        tx.outputs[0].value = 100000000; // dummy value for size estimation
        tx.output_count = 1;

        // For transfers, add a second output (recipient)
        if (tx_type == TX_TYPE_TRANSFER) {
            const char *recipient_hex = json_get_string(params, "recipient");
            if (recipient_hex) {
                noble_address_t recip_addr;
                if (parse_address_wire(recipient_hex, &recip_addr) == 0) {
                    tx.outputs[1].address = recip_addr;
                    tx.outputs[1].value = 50000000;
                    tx.output_count = 2;
                }
            } else {
                // Simulate a second output same size as change
                tx.outputs[1].address = change_addr;
                tx.outputs[1].value = 50000000;
                tx.output_count = 2;
            }
        }
    }

    // Sign and encode (probe pass) to measure exact CBOR size
    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    {
        int rc = sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id);
        if (rc != 0) {
            json_free(params);
            return json_emit_error(rc == -2
                ? "transaction exceeds MAX_TX_SIZE (8192 bytes)"
                : "size estimation failed");
        }
    }

    size_t size = cbor.len;
    noble_buf_free(&cbor);

    // Return size
    size_t bufsize = 64;
    char *result = (char *)malloc(bufsize);
    snprintf(result, bufsize, "{\"size\":%zu}", size);

    json_free(params);
    return result;
}

// ── CMS stubs (temporary — replaced by noble-cms-core binary module) ───

char *noble_sign_cms_ffi(const char *params_json) {
    (void)params_json;
    return strdup("{\"error\":\"CMS signing requires noble-cms-core module (not yet linked)\"}");
}

char *noble_verify_cms_ffi(const char *params_json) {
    (void)params_json;
    return strdup("{\"error\":\"CMS verification requires noble-cms-core module (not yet linked)\"}");
}

char *noble_import_pkcs12_ffi(const char *params_json) {
    (void)params_json;
    return strdup("{\"error\":\"PKCS#12 import requires noble-cms-core module (not yet linked)\"}");
}

// ── ECIES encrypt/decrypt (metadata field encryption) ──────────────────

#include "ecies.h"

char *noble_ecies_encrypt(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *plaintext_hex = json_get_string(params, "plaintext_hex");
    const char *pubkey_hex = json_get_string(params, "recipient_pubkey_hex");
    if (!plaintext_hex || !pubkey_hex) {
        json_free(params);
        return json_emit_error("missing plaintext_hex or recipient_pubkey_hex");
    }

    // Decode hex inputs
    size_t pt_hex_len = strlen(plaintext_hex);
    size_t pt_len = pt_hex_len / 2;
    uint8_t *plaintext = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
    if (!plaintext) { json_free(params); return json_emit_error("malloc failed"); }
    hex_decode(plaintext_hex, pt_hex_len, plaintext, pt_len);

    uint8_t pubkey[33];
    if (strlen(pubkey_hex) != 66 || hex_decode(pubkey_hex, 66, pubkey, 33) != 33) {
        free(plaintext);
        json_free(params);
        return json_emit_error("recipient_pubkey_hex must be 66 hex chars (33 bytes compressed)");
    }

    // Encrypt
    size_t payload_cap = pt_len + ECIES_OVERHEAD;
    uint8_t *payload = (uint8_t *)malloc(payload_cap);
    if (!payload) { free(plaintext); json_free(params); return json_emit_error("malloc failed"); }
    int payload_len = noble_ecies_encrypt_impl(plaintext, pt_len, pubkey, payload, payload_cap);
    free(plaintext);

    if (payload_len < 0) {
        free(payload);
        json_free(params);
        return json_emit_error("ECIES encryption failed");
    }

    // Hex-encode result
    char *payload_hex_out = (char *)malloc(payload_len * 2 + 1);
    if (!payload_hex_out) { free(payload); json_free(params); return json_emit_error("malloc failed"); }
    hex_encode(payload, payload_len, payload_hex_out);

    size_t bufsize = 32 + payload_len * 2;
    char *result = (char *)malloc(bufsize);
    if (!result) { free(payload_hex_out); free(payload); json_free(params); return json_emit_error("malloc failed"); }
    snprintf(result, bufsize, "{\"payload_hex\":\"%s\"}", payload_hex_out);

    free(payload_hex_out);
    free(payload);
    json_free(params);
    return result;
}

char *noble_ecies_decrypt(const char *params_json) {
    json_value_t *params = json_parse(params_json);
    if (!params) return json_emit_error("invalid JSON");

    const char *payload_hex = json_get_string(params, "payload_hex");
    const char *privkey_hex = json_get_string(params, "private_key_hex");
    if (!payload_hex || !privkey_hex) {
        json_free(params);
        return json_emit_error("missing payload_hex or private_key_hex");
    }

    size_t pay_hex_len = strlen(payload_hex);
    size_t pay_len = pay_hex_len / 2;
    uint8_t *payload = (uint8_t *)malloc(pay_len > 0 ? pay_len : 1);
    if (!payload) { json_free(params); return json_emit_error("malloc failed"); }
    hex_decode(payload_hex, pay_hex_len, payload, pay_len);

    uint8_t privkey[32];
    if (strlen(privkey_hex) != 64 || hex_decode(privkey_hex, 64, privkey, 32) != 32) {
        free(payload);
        json_free(params);
        return json_emit_error("private_key_hex must be 64 hex chars (32 bytes)");
    }

    size_t pt_cap = pay_len > 0 ? pay_len : 1;
    uint8_t *plaintext = (uint8_t *)malloc(pt_cap);
    if (!plaintext) { free(payload); json_free(params); return json_emit_error("malloc failed"); }
    int pt_len = noble_ecies_decrypt_impl(payload, pay_len, privkey, plaintext, pt_cap);
    free(payload);

    if (pt_len < 0) {
        free(plaintext);
        json_free(params);
        return json_emit_error("ECIES decryption failed (wrong key or corrupted payload)");
    }

    char *pt_hex = (char *)malloc(pt_len * 2 + 1);
    if (!pt_hex) { free(plaintext); json_free(params); return json_emit_error("malloc failed"); }
    hex_encode(plaintext, pt_len, pt_hex);
    free(plaintext);

    size_t bufsize = 32 + pt_len * 2;
    char *result = (char *)malloc(bufsize);
    if (!result) { free(pt_hex); json_free(params); return json_emit_error("malloc failed"); }
    snprintf(result, bufsize, "{\"plaintext_hex\":\"%s\"}", pt_hex);

    free(pt_hex);
    json_free(params);
    return result;
}

// ── noble_free ──────────────────────────────────────────────────────────

void noble_free(char *ptr) {
    free(ptr);
}
