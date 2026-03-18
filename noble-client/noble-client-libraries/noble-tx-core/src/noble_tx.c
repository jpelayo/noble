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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TX_TYPE_NOTARIZATION 0x00
#define TX_TYPE_TRANSFER     0x01
#define PROTOCOL_VERSION     1

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

    // Compute total input value for change.
    uint64_t input_total = 0;
    for (uint8_t i = 0; i < tx.input_count; i++) {
        // Input values come from the utxos array.
        const json_value_t *u = &utxos->array.items[i];
        input_total += json_get_uint(u, "value");
    }
    uint64_t change = input_total - amount - fee;
    if (change > 0) {
        noble_address_t change_addr;
        if (parse_address_wire(change_hex, &change_addr) != 0) {
            json_free(params);
            return json_emit_error("invalid change_address");
        }
        tx.outputs[tx.output_count].address = change_addr;
        tx.outputs[tx.output_count].value = change;
        tx.output_count++;
    }

    // Checksum is zero for transfers.
    memset(tx.checksum, 0, HASH256_LEN);

    // Timestamp = now (seconds since epoch).
    // Note: caller should set this via param if needed; default to 0 for determinism.
    tx.timestamp = json_get_uint(params, "timestamp");

    // Sign and encode.
    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    if (sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id) != 0) {
        json_free(params);
        return json_emit_error("signing failed");
    }

    // Emit result.
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

    // Output: change only (notarizations have no explicit recipient output).
    uint64_t change = input_total - fee;
    if (change > 0) {
        noble_address_t change_addr;
        if (parse_address_wire(change_hex, &change_addr) != 0) {
            json_free(params);
            return json_emit_error("invalid change_address");
        }
        tx.outputs[0].address = change_addr;
        tx.outputs[0].value = change;
        tx.output_count = 1;
    }

    tx.timestamp = json_get_uint(params, "timestamp");

    // Sign and encode.
    noble_buf_t cbor;
    uint8_t tx_id[HASH256_LEN];
    if (sign_and_encode_tx(&tx, private_key, chain_id, &cbor, tx_id) != 0) {
        json_free(params);
        return json_emit_error("signing failed");
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

// ── noble_free ──────────────────────────────────────────────────────────

void noble_free(char *ptr) {
    free(ptr);
}
