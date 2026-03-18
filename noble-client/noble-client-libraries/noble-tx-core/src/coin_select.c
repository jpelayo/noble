// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// 5-pass UTXO coin selection. Matches noble-client-core/src/coin_selection.rs.

#include "coin_select.h"
#include <string.h>
#include <stdlib.h>

static int cmp_asc(const void *a, const void *b) {
    uint64_t va = ((const noble_utxo_t *)a)->value;
    uint64_t vb = ((const noble_utxo_t *)b)->value;
    return (va > vb) - (va < vb);
}

static int cmp_desc(const void *a, const void *b) {
    uint64_t va = ((const noble_utxo_t *)a)->value;
    uint64_t vb = ((const noble_utxo_t *)b)->value;
    return (vb > va) - (vb < va);
}

static void set_result(noble_selection_t *r, const noble_utxo_t *sel, size_t count, uint64_t target) {
    r->count = count;
    r->total = 0;
    for (size_t i = 0; i < count; i++) {
        r->selected[i] = sel[i];
        r->total += sel[i].value;
    }
    r->change = r->total - target;
}

int coin_select(
    const noble_utxo_t *utxos,
    size_t utxo_count,
    uint64_t target,
    noble_selection_t *result
) {
    if (utxo_count == 0 || target == 0) return -1;

    // Work copy sorted ascending by value.
    noble_utxo_t sorted[MAX_UTXOS];
    size_t n = utxo_count < MAX_UTXOS ? utxo_count : MAX_UTXOS;
    memcpy(sorted, utxos, sizeof(noble_utxo_t) * n);
    qsort(sorted, n, sizeof(noble_utxo_t), cmp_asc);

    // Pass 1: Changeless exact match (1-3 UTXOs).
    for (size_t i = 0; i < n; i++) {
        if (sorted[i].value == target) {
            set_result(result, &sorted[i], 1, target);
            return 0;
        }
    }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (sorted[i].value + sorted[j].value == target) {
                noble_utxo_t pair[2] = { sorted[i], sorted[j] };
                set_result(result, pair, 2, target);
                return 0;
            }
        }
    }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            for (size_t k = j + 1; k < n; k++) {
                if (sorted[i].value + sorted[j].value + sorted[k].value == target) {
                    noble_utxo_t triple[3] = { sorted[i], sorted[j], sorted[k] };
                    set_result(result, triple, 3, target);
                    return 0;
                }
            }
        }
    }

    // Pass 2: Near-changeless (change < DUST_THRESHOLD).
    {
        uint64_t best_excess = UINT64_MAX;
        int best_idx = -1;
        for (size_t i = 0; i < n; i++) {
            if (sorted[i].value > target) {
                uint64_t excess = sorted[i].value - target;
                if (excess < DUST_THRESHOLD && excess < best_excess) {
                    best_excess = excess;
                    best_idx = (int)i;
                }
            }
        }
        if (best_idx >= 0) {
            set_result(result, &sorted[best_idx], 1, target);
            return 0;
        }
    }

    // Pass 3: Single best fit (smallest UTXO >= target).
    for (size_t i = 0; i < n; i++) {
        if (sorted[i].value >= target) {
            set_result(result, &sorted[i], 1, target);
            return 0;
        }
    }

    // Pass 4: Smallest-first accumulation.
    {
        uint64_t sum = 0;
        size_t count = 0;
        for (size_t i = 0; i < n && sum < target; i++) {
            sum += sorted[i].value;
            count = i + 1;
        }
        if (sum >= target) {
            set_result(result, sorted, count, target);
            return 0;
        }
    }

    // Pass 5: Largest-first accumulation.
    {
        noble_utxo_t desc[MAX_UTXOS];
        memcpy(desc, sorted, sizeof(noble_utxo_t) * n);
        qsort(desc, n, sizeof(noble_utxo_t), cmp_desc);
        uint64_t sum = 0;
        size_t count = 0;
        for (size_t i = 0; i < n && sum < target; i++) {
            sum += desc[i].value;
            count = i + 1;
        }
        if (sum >= target) {
            set_result(result, desc, count, target);
            return 0;
        }
    }

    return -1; // insufficient funds
}
