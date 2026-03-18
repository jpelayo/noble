// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! UTXO coin selection — five-pass algorithm.
//!
//! 1. Changeless exact match (1–3 UTXOs)
//! 2. Near-changeless (change < dust threshold)
//! 3. Single best fit (smallest UTXO covering target)
//! 4. Smallest-first accumulation (dust reduction)
//! 5. Largest-first fallback (guaranteed)

use serde::{Deserialize, Serialize};

/// A UTXO available for spending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

/// Select UTXOs to cover `target` groats.
pub fn select(available: &[Utxo], target: u64) -> Result<Vec<Utxo>, String> {
    let total: u64 = available.iter().map(|u| u.value).fold(0u64, |a, v| a.saturating_add(v));
    if total < target {
        return Err(format!(
            "Insufficient funds: have {total} groats, need {target}"
        ));
    }

    // Pass 1: Changeless — exact match with 1, 2, or 3 UTXOs.
    if let Some(exact) = find_exact(available, target, 0) {
        return Ok(exact);
    }

    // Pass 2: Near-changeless — change < dust threshold.
    if let Some(near) = find_exact(available, target, noble_core::DUST_THRESHOLD) {
        return Ok(near);
    }

    // Pass 3: Single best fit — smallest single UTXO ≥ target.
    if let Some(best) = available.iter().filter(|u| u.value >= target).min_by_key(|u| u.value) {
        return Ok(vec![best.clone()]);
    }

    // Pass 4: Smallest-first accumulation.
    let mut ascending: Vec<&Utxo> = available.iter().collect();
    ascending.sort_by_key(|u| u.value);
    if let Some(result) = accumulate(&ascending, target) {
        return Ok(result);
    }

    // Pass 5: Largest-first fallback.
    ascending.reverse();
    if let Some(result) = accumulate(&ascending, target) {
        return Ok(result);
    }

    Err(format!("Coin selection failed: have {total}, need {target}"))
}

fn find_exact(utxos: &[Utxo], target: u64, tolerance: u64) -> Option<Vec<Utxo>> {
    let n = utxos.len();

    for i in 0..n {
        let sum = utxos[i].value;
        if sum >= target && sum <= target.saturating_add(tolerance) {
            return Some(vec![utxos[i].clone()]);
        }
    }

    if n >= 2 {
        for i in 0..(n - 1) {
            for j in (i + 1)..n {
                let sum = utxos[i].value.saturating_add(utxos[j].value);
                if sum >= target && sum <= target.saturating_add(tolerance) {
                    return Some(vec![utxos[i].clone(), utxos[j].clone()]);
                }
            }
        }
    }

    if n >= 3 {
        for i in 0..(n - 2) {
            for j in (i + 1)..(n - 1) {
                for k in (j + 1)..n {
                    let sum = utxos[i].value.saturating_add(utxos[j].value).saturating_add(utxos[k].value);
                    if sum >= target && sum <= target.saturating_add(tolerance) {
                        return Some(vec![utxos[i].clone(), utxos[j].clone(), utxos[k].clone()]);
                    }
                }
            }
        }
    }

    None
}

fn accumulate(sorted: &[&Utxo], target: u64) -> Option<Vec<Utxo>> {
    let mut selected = Vec::new();
    let mut sum: u64 = 0;
    for utxo in sorted {
        selected.push((*utxo).clone());
        sum = sum.saturating_add(utxo.value);
        if sum >= target {
            return Some(selected);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_single() {
        let utxos = vec![
            Utxo { txid: "aa".repeat(32), vout: 0, value: 1000 },
            Utxo { txid: "bb".repeat(32), vout: 0, value: 500 },
        ];
        let selected = select(&utxos, 500).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 500);
    }

    #[test]
    fn exact_pair() {
        let utxos = vec![
            Utxo { txid: "aa".repeat(32), vout: 0, value: 300 },
            Utxo { txid: "bb".repeat(32), vout: 0, value: 200 },
        ];
        let selected = select(&utxos, 500).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn insufficient() {
        let utxos = vec![Utxo { txid: "aa".repeat(32), vout: 0, value: 50 }];
        assert!(select(&utxos, 100).is_err());
    }

    #[test]
    fn best_fit_avoids_sweep() {
        let utxos = vec![
            Utxo { txid: "aa".repeat(32), vout: 0, value: 1 },
            Utxo { txid: "bb".repeat(32), vout: 0, value: 2 },
            Utxo { txid: "cc".repeat(32), vout: 0, value: 5_000_000 },
        ];
        let selected = select(&utxos, 100).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 5_000_000);
    }
}
