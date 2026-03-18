// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// 5-pass UTXO coin selection algorithm.

#ifndef NOBLE_COIN_SELECT_H
#define NOBLE_COIN_SELECT_H

#include <stddef.h>
#include <stdint.h>

#define MAX_UTXOS 512
#define DUST_THRESHOLD 500000  // 500,000 groats

typedef struct {
    char     txid[65];  // hex-encoded, null-terminated
    uint32_t vout;
    uint64_t value;
} noble_utxo_t;

typedef struct {
    noble_utxo_t selected[MAX_UTXOS];
    size_t       count;
    uint64_t     total;
    uint64_t     change;  // total - target (0 if exact)
} noble_selection_t;

// Select UTXOs to cover target amount.
// 5-pass algorithm: changeless → near-changeless → single-best → smallest-first → largest-first.
// Returns 0 on success, -1 if insufficient funds.
int coin_select(
    const noble_utxo_t *utxos,
    size_t utxo_count,
    uint64_t target,
    noble_selection_t *result
);

#endif // NOBLE_COIN_SELECT_H
