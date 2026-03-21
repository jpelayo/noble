// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Minimal JSON parser for noble-tx-core input parameters.

#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

// ── Parser state ────────────────────────────────────────────────────────

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} parser_t;

static void skip_ws(parser_t *p) {
    while (p->pos < p->len && isspace((unsigned char)p->src[p->pos]))
        p->pos++;
}

static char peek(parser_t *p) {
    skip_ws(p);
    return p->pos < p->len ? p->src[p->pos] : '\0';
}

static char next(parser_t *p) {
    skip_ws(p);
    return p->pos < p->len ? p->src[p->pos++] : '\0';
}

static json_value_t *parse_value(parser_t *p);

static json_value_t *alloc_val(json_type_t type) {
    json_value_t *v = (json_value_t *)calloc(1, sizeof(json_value_t));
    if (v) v->type = type;
    return v;
}

static json_value_t *parse_string(parser_t *p) {
    if (next(p) != '"') return NULL;
    size_t start = p->pos;
    while (p->pos < p->len && p->src[p->pos] != '"') {
        if (p->src[p->pos] == '\\') p->pos++; // skip escaped char
        p->pos++;
    }
    size_t slen = p->pos - start;
    if (p->pos < p->len) p->pos++; // consume closing quote

    json_value_t *v = alloc_val(JSON_STRING);
    if (!v) return NULL;
    v->string.str = (char *)malloc(slen + 1);
    memcpy(v->string.str, p->src + start, slen);
    v->string.str[slen] = '\0';
    v->string.len = slen;
    return v;
}

static json_value_t *parse_number(parser_t *p) {
    skip_ws(p);
    char *end;
    double num = strtod(p->src + p->pos, &end);
    if (end == p->src + p->pos) return NULL;
    p->pos = (size_t)(end - p->src);
    json_value_t *v = alloc_val(JSON_NUMBER);
    if (v) v->number = num;
    return v;
}

static json_value_t *parse_array(parser_t *p) {
    if (next(p) != '[') return NULL;
    json_value_t *v = alloc_val(JSON_ARRAY);
    if (!v) return NULL;

    size_t cap = 16;
    v->array.items = (json_value_t *)malloc(sizeof(json_value_t) * cap);
    v->array.count = 0;

    if (peek(p) == ']') { p->pos++; return v; }

    while (1) {
        json_value_t *item = parse_value(p);
        if (!item) { json_free(v); return NULL; }
        if (v->array.count >= cap) {
            cap *= 2;
            v->array.items = (json_value_t *)realloc(v->array.items, sizeof(json_value_t) * cap);
        }
        v->array.items[v->array.count++] = *item;
        free(item);

        char c = peek(p);
        if (c == ',') { p->pos++; continue; }
        if (c == ']') { p->pos++; break; }
        json_free(v);
        return NULL;
    }
    return v;
}

static json_value_t *parse_object(parser_t *p) {
    if (next(p) != '{') return NULL;
    json_value_t *v = alloc_val(JSON_OBJECT);
    if (!v) return NULL;

    size_t cap = 16;
    v->object.keys = (char **)malloc(sizeof(char *) * cap);
    v->object.values = (json_value_t *)malloc(sizeof(json_value_t) * cap);
    v->object.count = 0;

    if (peek(p) == '}') { p->pos++; return v; }

    while (1) {
        json_value_t *key = parse_string(p);
        if (!key || key->type != JSON_STRING) { json_free(key); json_free(v); return NULL; }

        if (next(p) != ':') { json_free(key); json_free(v); return NULL; }

        json_value_t *val = parse_value(p);
        if (!val) { json_free(key); json_free(v); return NULL; }

        if (v->object.count >= cap) {
            cap *= 2;
            v->object.keys = (char **)realloc(v->object.keys, sizeof(char *) * cap);
            v->object.values = (json_value_t *)realloc(v->object.values, sizeof(json_value_t) * cap);
        }
        v->object.keys[v->object.count] = key->string.str;
        key->string.str = NULL;
        free(key);
        v->object.values[v->object.count] = *val;
        free(val);
        v->object.count++;

        char c = peek(p);
        if (c == ',') { p->pos++; continue; }
        if (c == '}') { p->pos++; break; }
        json_free(v);
        return NULL;
    }
    return v;
}

static json_value_t *parse_value(parser_t *p) {
    char c = peek(p);
    if (c == '"') return parse_string(p);
    if (c == '{') return parse_object(p);
    if (c == '[') return parse_array(p);
    if (c == '-' || isdigit((unsigned char)c)) return parse_number(p);
    if (strncmp(p->src + p->pos, "true", 4) == 0) {
        p->pos += 4;
        json_value_t *v = alloc_val(JSON_BOOL);
        if (v) v->boolean = 1;
        return v;
    }
    if (strncmp(p->src + p->pos, "false", 5) == 0) {
        p->pos += 5;
        json_value_t *v = alloc_val(JSON_BOOL);
        if (v) v->boolean = 0;
        return v;
    }
    if (strncmp(p->src + p->pos, "null", 4) == 0) {
        p->pos += 4;
        return alloc_val(JSON_NULL);
    }
    return NULL;
}

// ── Public API ──────────────────────────────────────────────────────────

json_value_t *json_parse(const char *input) {
    if (!input) return NULL;
    parser_t p = { input, 0, strlen(input) };
    return parse_value(&p);
}

void json_free(json_value_t *val) {
    if (!val) return;
    switch (val->type) {
    case JSON_STRING:
        free(val->string.str);
        break;
    case JSON_ARRAY:
        for (size_t i = 0; i < val->array.count; i++)
            json_free(&val->array.items[i]);
        free(val->array.items);
        val->array.items = NULL;
        val->array.count = 0;
        break;
    case JSON_OBJECT:
        for (size_t i = 0; i < val->object.count; i++) {
            free(val->object.keys[i]);
            json_free(&val->object.values[i]);
        }
        free(val->object.keys);
        free(val->object.values);
        val->object.keys = NULL;
        val->object.values = NULL;
        val->object.count = 0;
        break;
    default:
        break;
    }
}

const json_value_t *json_get(const json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->object.count; i++) {
        if (strcmp(obj->object.keys[i], key) == 0)
            return &obj->object.values[i];
    }
    return NULL;
}

const char *json_get_string(const json_value_t *obj, const char *key) {
    const json_value_t *v = json_get(obj, key);
    if (v && v->type == JSON_STRING) return v->string.str;
    return NULL;
}

uint64_t json_get_uint(const json_value_t *obj, const char *key) {
    const json_value_t *v = json_get(obj, key);
    if (v && v->type == JSON_NUMBER) return (uint64_t)v->number;
    return 0;
}

uint32_t json_get_uint32(const json_value_t *obj, const char *key) {
    return (uint32_t)json_get_uint(obj, key);
}

// ── JSON emitters ───────────────────────────────────────────────────────

char *json_emit_result(const char *tx_hex, const char *tx_id) {
    size_t len = strlen(tx_hex) + strlen(tx_id) + 64;
    char *out = (char *)malloc(len);
    snprintf(out, len, "{\"tx_hex\":\"%s\",\"tx_id\":\"%s\"}", tx_hex, tx_id);
    return out;
}

char *json_emit_result_with_fee(const char *tx_hex, const char *tx_id, uint64_t fee, size_t size_bytes) {
    size_t len = strlen(tx_hex) + strlen(tx_id) + 128;
    char *out = (char *)malloc(len);
    snprintf(out, len, "{\"tx_hex\":\"%s\",\"tx_id\":\"%s\",\"fee\":%llu,\"size\":%zu}",
             tx_hex, tx_id, (unsigned long long)fee, size_bytes);
    return out;
}

char *json_emit_error(const char *message) {
    size_t len = strlen(message) + 32;
    char *out = (char *)malloc(len);
    snprintf(out, len, "{\"error\":\"%s\"}", message);
    return out;
}
