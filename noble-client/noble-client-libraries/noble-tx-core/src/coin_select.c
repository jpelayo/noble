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

    // Overflow guard: if the grand total of all values overflows u64 the inputs
    // are malformed (real chain values sum well below u64 max). With a
    // non-overflowing grand total, every subset sum below (pair/triple/
    // accumulation) is ≤ total and therefore also overflow-free.
    {
        uint64_t grand = 0;
        for (size_t i = 0; i < n; i++) {
            if (grand > UINT64_MAX - sorted[i].value) return -1;
            grand += sorted[i].value;
        }
    }

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

// Effective-value coin selection. Each UTXO contributes `value - fee_per_input`
// toward `target` (which EXCLUDES per-input cost); UTXOs worth no more than
// `fee_per_input` are skipped as uneconomic. With `fee_per_input == 0` this is
// bit-identical to `coin_select` (the regression anchor). Otherwise it runs the
// same 5-pass algorithm over effective values, then maps the selection back to
// raw values for the result:
//   result->total  = Σ raw value of selected
//   result->change = Σ effective value − target = total − count·fee_per_input − target
//                  = the true on-chain change (caller passes a per-input-free target).
int coin_select_ev(
    const noble_utxo_t *utxos,
    size_t utxo_count,
    uint64_t target,
    uint64_t fee_per_input,
    noble_selection_t *result
) {
    if (fee_per_input == 0) {
        return coin_select(utxos, utxo_count, target, result);
    }
    if (utxo_count == 0 || target == 0) return -1;

    // Build economic candidates: raw kept verbatim, effective copy = value - fee.
    noble_utxo_t raw[MAX_UTXOS];
    noble_utxo_t eff[MAX_UTXOS];
    size_t m = 0;
    size_t n = utxo_count < MAX_UTXOS ? utxo_count : MAX_UTXOS;
    for (size_t i = 0; i < n; i++) {
        if (utxos[i].value > fee_per_input) { // strictly economic ⇒ effective > 0
            raw[m] = utxos[i];
            eff[m] = utxos[i];
            eff[m].value = utxos[i].value - fee_per_input;
            m++;
        }
    }
    if (m == 0) return -1;

    noble_selection_t ev_sel;
    if (coin_select(eff, m, target, &ev_sel) != 0) return -1;

    // Map the selected effective UTXOs back to their raw values.
    result->count = ev_sel.count;
    result->total = 0;
    uint64_t ev_total = 0;
    for (size_t i = 0; i < ev_sel.count; i++) {
        ev_total += ev_sel.selected[i].value; // effective value
        // Recover the raw UTXO by identity (txid + vout).
        int found = 0;
        for (size_t j = 0; j < m; j++) {
            if (raw[j].vout == ev_sel.selected[i].vout
                && strcmp(raw[j].txid, ev_sel.selected[i].txid) == 0) {
                result->selected[i] = raw[j];
                result->total += raw[j].value;
                found = 1;
                break;
            }
        }
        // Every selected effective UTXO was copied from `eff` (built in lockstep
        // with `raw`), so a match is guaranteed in practice. Bail rather than
        // leave `result->selected[i]` uninitialized / under-count `total` if
        // that invariant is ever violated.
        if (!found) return -1;
    }
    // Σ ev − target  ==  total − count·fee_per_input − target  (true change).
    result->change = ev_total - target;
    return 0;
}
