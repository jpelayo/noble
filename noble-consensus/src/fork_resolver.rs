// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Automatic fork resolution state machine.
//!
//! Pure decision logic — no I/O.  The node feeds fork data via
//! `CycleEvent::ForkStatus` and acts on `CycleIo::RequestForkResolution`.

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkResolutionStrategy {
    /// Alert only — never auto-resolve.
    Manual,
    /// Resolve when >66% of peers are on a different fork.
    PeerSupermajority,
    /// Resolve when a fork is >3 blocks ahead of the local chain.
    LongestChain,
}

/// Fork info fed from node.rs (same data as `getDetectedForks` RPC).
#[derive(Debug, Clone)]
pub struct ForkInfo {
    pub tip_hash: Hash256,
    pub height: u64,
    pub peer_count: usize,
    pub is_local: bool,
}

/// Resolution decision returned by `evaluate()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkDecision {
    /// No action required.
    NoAction,
    /// Threshold met but dwell timer not expired.
    Pending { cycles_remaining: u32 },
    /// Auto-resolve: reset chain and re-sync to the target.
    Resolve {
        target_hash: Hash256,
        target_height: u64,
        reason: String,
    },
}

/// Pure fork resolution state machine.
pub struct ForkResolver {
    strategy: ForkResolutionStrategy,
    /// Minimum cycles a fork must persist before resolution (default: 3).
    min_fork_duration: u32,
    /// Current dwell counter (incremented each evaluation where threshold is met).
    fork_dwell_counter: u32,
    /// Hash of the fork we're tracking (reset if dominant fork changes).
    tracked_fork_hash: Option<Hash256>,
    /// Finalized height floor — never resolve past this.
    finalized_height: u64,
}

impl ForkResolver {
    pub fn new(strategy: ForkResolutionStrategy, min_fork_duration: u32) -> Self {
        Self {
            strategy,
            min_fork_duration,
            fork_dwell_counter: 0,
            tracked_fork_hash: None,
            finalized_height: 0,
        }
    }

    /// Evaluate fork data and return a resolution decision.
    ///
    /// Called once per cycle boundary (or at a regular interval) with:
    /// - `local_height`: our committed chain tip
    /// - `forks`: all known fork groups (including the local one)
    /// - `total_peers`: total number of connected peers
    pub fn evaluate(
        &mut self,
        local_height: u64,
        forks: &[ForkInfo],
        total_peers: usize,
    ) -> ForkDecision {
        // Manual strategy never auto-resolves.
        if self.strategy == ForkResolutionStrategy::Manual {
            return ForkDecision::NoAction;
        }

        // No peers → no resolution possible.
        if total_peers == 0 {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Find the dominant non-local fork (highest peer_count, then height).
        let dominant = forks
            .iter()
            .filter(|f| !f.is_local)
            .max_by_key(|f| (f.peer_count, f.height));

        let dominant = match dominant {
            Some(d) => d,
            None => {
                self.reset_tracking();
                return ForkDecision::NoAction;
            }
        };

        // Check strategy threshold.
        let threshold_met = match self.strategy {
            ForkResolutionStrategy::PeerSupermajority => {
                // >66%: dominant_peers * 3 > total_peers * 2
                dominant.peer_count * 3 > total_peers * 2
            }
            ForkResolutionStrategy::LongestChain => {
                // Fork is >3 blocks ahead.
                dominant.height > local_height + 3
            }
            ForkResolutionStrategy::Manual => false,
        };

        if !threshold_met {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Safety: never resolve past finalized height.
        if dominant.height <= self.finalized_height {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Track the fork hash — if it changed, reset dwell counter.
        if self.tracked_fork_hash != Some(dominant.tip_hash) {
            self.tracked_fork_hash = Some(dominant.tip_hash);
            self.fork_dwell_counter = 0;
        }

        self.fork_dwell_counter += 1;

        if self.fork_dwell_counter < self.min_fork_duration {
            return ForkDecision::Pending {
                cycles_remaining: self.min_fork_duration - self.fork_dwell_counter,
            };
        }

        // Dwell expired — resolve.
        let reason = match self.strategy {
            ForkResolutionStrategy::PeerSupermajority => format!(
                "peer supermajority ({}/{} peers) on fork at height {}",
                dominant.peer_count, total_peers, dominant.height
            ),
            ForkResolutionStrategy::LongestChain => format!(
                "fork {} blocks ahead (local={}, fork={})",
                dominant.height.saturating_sub(local_height),
                local_height,
                dominant.height
            ),
            ForkResolutionStrategy::Manual => unreachable!(),
        };

        let decision = ForkDecision::Resolve {
            target_hash: dominant.tip_hash,
            target_height: dominant.height,
            reason,
        };

        self.reset_tracking();
        decision
    }

    fn reset_tracking(&mut self) {
        self.fork_dwell_counter = 0;
        self.tracked_fork_hash = None;
    }

    // ── Public accessors ──

    pub fn strategy(&self) -> ForkResolutionStrategy {
        self.strategy
    }

    pub fn dwell_counter(&self) -> u32 {
        self.fork_dwell_counter
    }

    pub fn min_fork_duration(&self) -> u32 {
        self.min_fork_duration
    }

    pub fn tracked_fork_hash(&self) -> Option<Hash256> {
        self.tracked_fork_hash
    }

    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub fn set_strategy(&mut self, strategy: ForkResolutionStrategy) {
        self.strategy = strategy;
        self.reset_tracking();
    }

    pub fn set_finalized_height(&mut self, height: u64) {
        self.finalized_height = height;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Hash256::from_bytes(bytes)
    }

    fn local_fork(height: u64) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(0),
            height,
            peer_count: 1,
            is_local: true,
        }
    }

    fn remote_fork(id: u8, height: u64, peer_count: usize) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
        }
    }

    #[test]
    fn manual_strategy_never_resolves() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::Manual, 3);
        let forks = vec![local_fork(5), remote_fork(1, 100, 10)];
        assert_eq!(fr.evaluate(5, &forks, 10), ForkDecision::NoAction);
    }

    #[test]
    fn peer_supermajority_triggers() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 1);
        // 3/4 peers on fork = 75% > 66%
        let forks = vec![local_fork(5), remote_fork(1, 5, 3)];
        let result = fr.evaluate(5, &forks, 4);
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 5),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn peer_supermajority_below_threshold() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 3);
        // 1/3 peers on fork = 33% < 66%
        let forks = vec![local_fork(5), remote_fork(1, 5, 1)];
        assert_eq!(fr.evaluate(5, &forks, 3), ForkDecision::NoAction);
    }

    #[test]
    fn longest_chain_triggers() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 1);
        // Fork 4 blocks ahead (local=5, fork=9, diff=4 > 3)
        let forks = vec![local_fork(5), remote_fork(1, 9, 2)];
        let result = fr.evaluate(5, &forks, 3);
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 9),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn longest_chain_below_threshold() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 3);
        // Fork 2 blocks ahead (local=5, fork=7, diff=2 <= 3)
        let forks = vec![local_fork(5), remote_fork(1, 7, 2)];
        assert_eq!(fr.evaluate(5, &forks, 3), ForkDecision::NoAction);
    }

    #[test]
    fn dwell_timer_delays_resolution() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 3);
        let forks = vec![local_fork(5), remote_fork(1, 20, 2)];

        // First evaluation: dwell starts
        assert_eq!(
            fr.evaluate(5, &forks, 3),
            ForkDecision::Pending {
                cycles_remaining: 2
            }
        );
        // Second
        assert_eq!(
            fr.evaluate(5, &forks, 3),
            ForkDecision::Pending {
                cycles_remaining: 1
            }
        );
        // Third: dwell expired → resolve
        match fr.evaluate(5, &forks, 3) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 20),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn fork_change_resets_dwell() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 3);

        // Fork A — accumulate 2 dwell ticks
        let forks_a = vec![local_fork(5), remote_fork(1, 20, 2)];
        assert!(matches!(
            fr.evaluate(5, &forks_a, 3),
            ForkDecision::Pending { .. }
        ));
        assert!(matches!(
            fr.evaluate(5, &forks_a, 3),
            ForkDecision::Pending { .. }
        ));
        assert_eq!(fr.dwell_counter(), 2);

        // Fork B replaces A — dwell resets
        let forks_b = vec![local_fork(5), remote_fork(2, 25, 2)];
        let result = fr.evaluate(5, &forks_b, 3);
        assert_eq!(
            result,
            ForkDecision::Pending {
                cycles_remaining: 2
            }
        );
        assert_eq!(fr.dwell_counter(), 1);
    }

    #[test]
    fn never_resolves_past_finality() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 1);
        fr.set_finalized_height(10);
        // Fork at height 8 — below finalized
        let forks = vec![local_fork(5), remote_fork(1, 8, 5)];
        assert_eq!(fr.evaluate(5, &forks, 5), ForkDecision::NoAction);
    }

    #[test]
    fn no_peers_no_resolution() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 1);
        let forks = vec![local_fork(5)];
        assert_eq!(fr.evaluate(5, &forks, 0), ForkDecision::NoAction);
    }

    #[test]
    fn strategy_change_resets_state() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestChain, 3);
        let forks = vec![local_fork(5), remote_fork(1, 20, 2)];
        fr.evaluate(5, &forks, 3);
        assert_eq!(fr.dwell_counter(), 1);

        fr.set_strategy(ForkResolutionStrategy::PeerSupermajority);
        assert_eq!(fr.dwell_counter(), 0);
        assert_eq!(fr.tracked_fork_hash(), None);
    }
}
