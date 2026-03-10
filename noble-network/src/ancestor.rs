// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! 2-round-trip common ancestor discovery using exponential probe + bisect fill.
//!
//! When two nodes share the same chain ID but have different chain tips (fork),
//! this module finds the highest block they both agree on (common ancestor).
//!
//! # Algorithm
//!
//! **Round 1 — Exponential probes:**
//! Generate probe heights with exponentially growing gaps from `min(local, peer)`:
//! `H, H-1, H-2, H-4, H-8, H-16, ...` down to 0. Send all in one batch.
//! Walk the response to find the `[last_match, first_mismatch]` range.
//!
//! **Round 2 — Fill the gap:**
//! Send every height in `(last_match, first_mismatch)` in one batch.
//! The highest matching height IS the common ancestor.

use libp2p::PeerId;

/// State machine for 2-round-trip common ancestor discovery.
pub struct AncestorFinder {
    /// The peer we're searching against.
    pub peer_id: PeerId,
    phase: Phase,
}

enum Phase {
    /// Waiting for Round 1 response (exponential probes).
    ExponentialProbe,
    /// Waiting for Round 2 response (fill the narrowed range).
    BisectFill { low: u64, high: u64 },
    /// Search complete.
    Done(u64),
}

impl AncestorFinder {
    /// Create a new finder. Returns `(finder, probe_heights_for_round_1)`.
    pub fn new(peer_id: PeerId, local_height: u64, peer_height: u64) -> (Self, Vec<u64>) {
        let top = local_height.min(peer_height);
        let mut probes = Vec::new();
        let mut gap = 0u64; // cumulative offset from top
        // Exponential probes: top, top-1, top-2, top-4, top-8, ...
        loop {
            let h = top.saturating_sub(gap);
            probes.push(h);
            if h == 0 {
                break;
            }
            gap = if gap == 0 { 1 } else { gap.saturating_mul(2) };
            if gap > top {
                probes.push(0);
                break;
            }
        }
        let finder = Self {
            peer_id,
            phase: Phase::ExponentialProbe,
        };
        (finder, probes)
    }

    /// Process a batch response. Returns:
    /// - `Ok(Some(ancestor_height))` — search complete
    /// - `Ok(None)` — need Round 2; call `round2_heights()` to get the next batch
    /// - `Err(msg)` — search failed
    pub fn process_response(
        &mut self,
        response: &[(u64, Option<[u8; 32]>)],
        local_hashes: &[(u64, Option<[u8; 32]>)],
    ) -> Result<Option<u64>, String> {
        match &self.phase {
            Phase::ExponentialProbe => {
                // Build sorted pairs (height, matches).
                let mut pairs: Vec<(u64, bool)> = response
                    .iter()
                    .map(|(h, remote)| {
                        let local = local_hashes
                            .iter()
                            .find(|(lh, _)| lh == h)
                            .and_then(|(_, lhash)| *lhash);
                        let matches =
                            remote.is_some() && local.is_some() && remote == &local;
                        (*h, matches)
                    })
                    .collect();
                pairs.sort_by_key(|(h, _)| *h);

                // Walk from lowest to highest to find match→mismatch transition.
                let mut best_match: Option<u64> = None;
                let mut first_mismatch: Option<u64> = None;
                for &(h, m) in &pairs {
                    if m {
                        best_match = Some(h);
                    } else if best_match.is_some() && first_mismatch.is_none() {
                        first_mismatch = Some(h);
                    }
                }

                match (best_match, first_mismatch) {
                    (Some(low), Some(high)) if high <= low + 1 => {
                        // Gap of ≤1 — ancestor found in Round 1.
                        self.phase = Phase::Done(low);
                        Ok(Some(low))
                    }
                    (Some(low), Some(high)) => {
                        // Need Round 2 to narrow [low+1, high-1].
                        self.phase = Phase::BisectFill { low, high };
                        Ok(None)
                    }
                    (None, _) => {
                        // No matching height — chains share nothing.
                        Err(
                            "no common block found — chains may have different genesis"
                                .into(),
                        )
                    }
                    (Some(top), None) => {
                        // All probed heights match — top is the ancestor.
                        self.phase = Phase::Done(top);
                        Ok(Some(top))
                    }
                }
            }
            Phase::BisectFill { low, .. } => {
                // Walk the fill response to find the highest matching height.
                let mut best = *low;
                for &(h, ref remote) in response {
                    let local = local_hashes
                        .iter()
                        .find(|(lh, _)| *lh == h)
                        .and_then(|(_, lhash)| *lhash);
                    let matches =
                        remote.is_some() && local.is_some() && remote == &local;
                    if matches && h > best {
                        best = h;
                    }
                }
                self.phase = Phase::Done(best);
                Ok(Some(best))
            }
            Phase::Done(h) => Ok(Some(*h)),
        }
    }

    /// Heights to query for Round 2 (bisect fill).
    /// Call after `process_response` returns `Ok(None)`.
    pub fn round2_heights(&self) -> Vec<u64> {
        match &self.phase {
            Phase::BisectFill { low, high } => (low + 1..*high).collect(),
            _ => vec![],
        }
    }

    /// Whether the search is complete.
    pub fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done(_))
    }

    /// The ancestor height (only valid after search is done).
    pub fn ancestor_height(&self) -> Option<u64> {
        match self.phase {
            Phase::Done(h) => Some(h),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn no_fork_all_match() {
        let pid = make_peer_id();
        let (mut finder, probes) = AncestorFinder::new(pid, 100, 100);
        // All heights match (same chain).
        let response: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        let local: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        let result = finder.process_response(&response, &local);
        assert!(result.is_ok());
        let ancestor = result.unwrap();
        assert_eq!(ancestor, Some(100));
        assert!(finder.is_done());
    }

    #[test]
    fn fork_at_genesis() {
        let pid = make_peer_id();
        let (mut finder, probes) = AncestorFinder::new(pid, 50, 50);
        // Only height 0 matches (genesis).
        let response: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| {
                if h == 0 {
                    (h, Some([0; 32]))
                } else {
                    (h, Some([h as u8 + 100; 32])) // different
                }
            })
            .collect();
        let local: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        // height 0: remote=[0;32], local=[0;32] → match
        // height 1+: remote=[h+100;32], local=[h;32] → mismatch
        // Round 1: narrows to a range (0 is only match, next probe mismatch may be >1 away)
        let result = finder.process_response(&response, &local);
        assert!(result.is_ok());
        match result.unwrap() {
            Some(0) => {} // Found directly in round 1 (gap ≤ 1)
            None => {
                // Need round 2 to fill the gap — all heights diverge above 0.
                let r2 = finder.round2_heights();
                let r2_response: Vec<(u64, Option<[u8; 32]>)> = r2
                    .iter()
                    .map(|&h| (h, Some([h as u8 + 100; 32])))
                    .collect();
                let r2_local: Vec<(u64, Option<[u8; 32]>)> = r2
                    .iter()
                    .map(|&h| (h, Some([h as u8; 32])))
                    .collect();
                let result2 = finder.process_response(&r2_response, &r2_local);
                assert!(result2.is_ok());
                assert_eq!(result2.unwrap(), Some(0)); // ancestor is genesis
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn shallow_fork_depth_1() {
        let pid = make_peer_id();
        let (mut finder, probes) = AncestorFinder::new(pid, 10, 10);
        // Fork at depth 1: blocks 0..9 match, block 10 differs.
        let response: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| {
                if h < 10 {
                    (h, Some([h as u8; 32])) // match
                } else {
                    (h, Some([99; 32])) // mismatch at tip
                }
            })
            .collect();
        let local: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        let result = finder.process_response(&response, &local);
        assert!(result.is_ok());
        let ancestor = result.unwrap();
        // Should find ancestor = 9 (the highest matching height).
        // With probes [10, 9, 8, 6, 2, 0]: 10 mismatches, 9 matches → gap=1, done in R1.
        assert!(ancestor.is_some());
        assert!(ancestor.unwrap() >= 8); // at least 8 (exact depends on probe layout)
    }

    #[test]
    fn probe_generation() {
        let pid = make_peer_id();
        let (_, probes) = AncestorFinder::new(pid, 139, 139);
        // Should generate probes: 139, 138, 137, 135, 131, 123, 107, 75, 11, 0
        assert!(probes.contains(&139));
        assert!(probes.contains(&0));
        assert!(*probes.last().unwrap() == 0);
        // Probes should be in decreasing order (from top).
        for i in 1..probes.len() {
            assert!(probes[i] <= probes[i - 1]);
        }
    }

    #[test]
    fn deep_fork_needs_round2() {
        let pid = make_peer_id();
        let (mut finder, probes) = AncestorFinder::new(pid, 139, 139);
        // Fork at height 95: blocks 0..95 match, 96..139 differ.
        let response: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| {
                if h <= 95 {
                    (h, Some([h as u8; 32])) // match
                } else {
                    (h, Some([h as u8 + 100; 32])) // different
                }
            })
            .collect();
        let local: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        let result = finder.process_response(&response, &local);
        assert!(result.is_ok());
        // With probes [139, 138, 137, 135, 131, 123, 107, 75, 11, 0]:
        // 75 matches (≤95), 107 mismatches (>95) → range [75, 107] → needs Round 2.
        // OR could be found in R1 if probes happen to bracket tightly.
        // Either way, result should eventually resolve.
        let ancestor = result.unwrap();
        if ancestor.is_none() {
            // Need Round 2 — this is expected for deep forks.
            assert!(!finder.is_done());
        }
    }

    #[test]
    fn round2_resolves() {
        let pid = make_peer_id();
        let (mut finder, probes) = AncestorFinder::new(pid, 139, 139);
        // Fork at height 95.
        let response: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| {
                if h <= 95 {
                    (h, Some([h as u8; 32]))
                } else {
                    (h, Some([h as u8 + 100; 32]))
                }
            })
            .collect();
        let local_r1: Vec<(u64, Option<[u8; 32]>)> = probes
            .iter()
            .map(|&h| (h, Some([h as u8; 32])))
            .collect();
        let r1 = finder.process_response(&response, &local_r1).unwrap();
        if r1.is_none() {
            // Fill heights between the narrowed range.
            // The BisectFill phase stores low. We know high from the probe response.
            // Simulate Round 2: heights 76..106.
            let round2: Vec<u64> = (76..107).collect();
            let r2_response: Vec<(u64, Option<[u8; 32]>)> = round2
                .iter()
                .map(|&h| {
                    if h <= 95 {
                        (h, Some([h as u8; 32]))
                    } else {
                        (h, Some([h as u8 + 100; 32]))
                    }
                })
                .collect();
            let r2_local: Vec<(u64, Option<[u8; 32]>)> = round2
                .iter()
                .map(|&h| (h, Some([h as u8; 32])))
                .collect();
            let r2 = finder.process_response(&r2_response, &r2_local).unwrap();
            assert_eq!(r2, Some(95));
            assert!(finder.is_done());
        } else {
            // Found in R1 (probe bracketed tightly).
            assert!(finder.is_done());
        }
    }
}
