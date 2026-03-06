// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Finality tracking for the NOBLE consensus engine.
//!
//! Counts consecutive clean cycles after block commit and declares blocks
//! **finalized** (immune to reorg) after a configurable threshold.

use noble_crypto::Hash256;
use std::collections::VecDeque;

/// Tracks block finality by counting consecutive clean cycles.
///
/// After `confirmation_threshold` consecutive cycles where each committed
/// block builds on the previous (no fork), the oldest unfinalized block
/// graduates to "finalized" — immune to any reorg or reset.
#[derive(Debug, Clone)]
pub struct FinalityTracker {
    /// Highest height that has achieved finality.
    pub finalized_height: u64,
    /// Hash of the block at finalized_height.
    pub finalized_hash: Hash256,
    /// Cycle at which finalized_height was declared final.
    pub finalized_at_cycle: u64,
    /// Confirmation threshold (number of consecutive cycles required).
    confirmation_threshold: u32,
    /// Ring buffer of recent commits: (height, hash, cycle).
    /// Capped to `confirmation_threshold + 1` entries.
    cycle_commits: VecDeque<(u64, Hash256, u64)>,
}

/// Finality status for a given block height.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum FinalityStatus {
    /// Just committed, no confirmations yet.
    Committed,
    /// Has `n` of `threshold` required confirmations.
    Confirmed { confirmations: u32, threshold: u32 },
    /// Immune to reorg.
    Finalized,
}

impl FinalityTracker {
    /// Create a new finality tracker with the given confirmation threshold.
    pub fn new(confirmation_threshold: u32) -> Self {
        Self {
            finalized_height: 0,
            finalized_hash: Hash256::ZERO,
            finalized_at_cycle: 0,
            confirmation_threshold,
            cycle_commits: VecDeque::new(),
        }
    }

    /// Record a block commit for finality tracking.
    pub fn on_block_committed(&mut self, height: u64, hash: Hash256, cycle: u64) {
        self.cycle_commits.push_back((height, hash, cycle));
        // Cap ring buffer size.
        while self.cycle_commits.len() > (self.confirmation_threshold as usize) + 1 {
            self.cycle_commits.pop_front();
        }
        self.check_finality();
    }

    /// Check if finality can advance.
    ///
    /// If the ring buffer has more than `confirmation_threshold` entries AND
    /// all entries form a monotonic height sequence (each = previous + 1),
    /// advance `finalized_height` to the oldest entry and pop it.
    fn check_finality(&mut self) {
        while self.cycle_commits.len() > self.confirmation_threshold as usize {
            // Verify monotonic height sequence.
            let mut monotonic = true;
            for i in 1..self.cycle_commits.len() {
                if self.cycle_commits[i].0 != self.cycle_commits[i - 1].0 + 1 {
                    monotonic = false;
                    break;
                }
            }
            if !monotonic {
                break;
            }
            // Advance finality to oldest entry.
            let (height, hash, cycle) = self.cycle_commits.pop_front().unwrap();
            if height > self.finalized_height {
                self.finalized_height = height;
                self.finalized_hash = hash;
                self.finalized_at_cycle = cycle;
            }
        }
    }

    /// How many consecutive clean cycles the current tip has.
    pub fn confirmations_for_tip(&self) -> u32 {
        if self.cycle_commits.is_empty() {
            return 0;
        }
        // Count consecutive monotonic entries from the back.
        let len = self.cycle_commits.len();
        let mut count = 1u32;
        for i in (1..len).rev() {
            if self.cycle_commits[i].0 == self.cycle_commits[i - 1].0 + 1 {
                count += 1;
            } else {
                break;
            }
        }
        // Subtract 1 because the first entry is the base (0 confirmations).
        count.saturating_sub(1).min(self.confirmation_threshold)
    }

    /// Get the finality status for a given height.
    pub fn status_for_height(&self, height: u64) -> FinalityStatus {
        if height == 0 {
            return FinalityStatus::Committed;
        }
        if height <= self.finalized_height {
            return FinalityStatus::Finalized;
        }
        let confirmations = self.confirmations_for_height(height);
        if confirmations > 0 {
            FinalityStatus::Confirmed {
                confirmations,
                threshold: self.confirmation_threshold,
            }
        } else {
            FinalityStatus::Committed
        }
    }

    /// Get the confirmation threshold.
    pub fn confirmation_threshold(&self) -> u32 {
        self.confirmation_threshold
    }

    /// Restore finality state from storage on startup.
    pub fn restore(&mut self, height: u64, hash: Hash256, cycle: u64) {
        self.finalized_height = height;
        self.finalized_hash = hash;
        self.finalized_at_cycle = cycle;
    }

    /// Reset cycle commits (used by `reset_tip`).
    /// Preserves finalized_height when not resetting to 0.
    pub fn reset(&mut self) {
        self.cycle_commits.clear();
    }

    /// Reset everything including finalized state (used for full chain reset).
    pub fn reset_full(&mut self) {
        self.cycle_commits.clear();
        self.finalized_height = 0;
        self.finalized_hash = Hash256::ZERO;
        self.finalized_at_cycle = 0;
    }

    /// Count confirmations for a specific height.
    fn confirmations_for_height(&self, height: u64) -> u32 {
        // Find the position of this height in the ring buffer.
        let pos = self.cycle_commits.iter().position(|(h, _, _)| *h == height);
        match pos {
            Some(idx) => {
                // Count how many monotonic entries follow this one.
                let mut count = 0u32;
                for i in (idx + 1)..self.cycle_commits.len() {
                    if self.cycle_commits[i].0 == self.cycle_commits[i - 1].0 + 1 {
                        count += 1;
                    } else {
                        break;
                    }
                }
                count.min(self.confirmation_threshold)
            }
            None => 0,
        }
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

    #[test]
    fn test_finality_advances_after_threshold() {
        let mut ft = FinalityTracker::new(3);
        // 4 sequential commits: heights 1,2,3,4 over cycles 1,2,3,4.
        ft.on_block_committed(1, hash(1), 1);
        assert_eq!(ft.finalized_height, 0);
        ft.on_block_committed(2, hash(2), 2);
        assert_eq!(ft.finalized_height, 0);
        ft.on_block_committed(3, hash(3), 3);
        assert_eq!(ft.finalized_height, 0);
        ft.on_block_committed(4, hash(4), 4);
        // After 4 commits with threshold=3, height 1 should be finalized.
        assert_eq!(ft.finalized_height, 1);
        assert_eq!(ft.finalized_hash, hash(1));
        assert_eq!(ft.finalized_at_cycle, 1);

        // Commit height 5 → height 2 becomes finalized.
        ft.on_block_committed(5, hash(5), 5);
        assert_eq!(ft.finalized_height, 2);
    }

    #[test]
    fn test_finality_does_not_advance_on_fork() {
        let mut ft = FinalityTracker::new(3);
        ft.on_block_committed(1, hash(1), 1);
        ft.on_block_committed(2, hash(2), 2);
        // Same height repeated = fork/empty cycle — breaks monotonic sequence.
        ft.on_block_committed(2, hash(20), 3);
        ft.on_block_committed(3, hash(3), 4);
        // Finality should NOT have advanced (sequence broken at height 2→2).
        assert_eq!(ft.finalized_height, 0);
    }

    #[test]
    fn test_finality_only_advances() {
        let mut ft = FinalityTracker::new(2);
        ft.on_block_committed(1, hash(1), 1);
        ft.on_block_committed(2, hash(2), 2);
        ft.on_block_committed(3, hash(3), 3);
        assert_eq!(ft.finalized_height, 1);
        // Finalized height should never decrease.
        ft.on_block_committed(4, hash(4), 4);
        assert!(ft.finalized_height >= 1);
        assert_eq!(ft.finalized_height, 2);
    }

    #[test]
    fn test_confirmations_for_tip() {
        let mut ft = FinalityTracker::new(3);
        assert_eq!(ft.confirmations_for_tip(), 0);

        ft.on_block_committed(1, hash(1), 1);
        assert_eq!(ft.confirmations_for_tip(), 0);

        ft.on_block_committed(2, hash(2), 2);
        assert_eq!(ft.confirmations_for_tip(), 1);

        ft.on_block_committed(3, hash(3), 3);
        assert_eq!(ft.confirmations_for_tip(), 2);

        // After 4th commit, height 1 is finalized and popped from the buffer.
        // Buffer is now [2,3,4] → tip has 2 confirmations (still building toward next finalization).
        ft.on_block_committed(4, hash(4), 4);
        assert_eq!(ft.confirmations_for_tip(), 2);
        assert_eq!(ft.finalized_height, 1);

        // After 5th commit, height 2 is finalized. Buffer: [3,4,5] → tip has 2 confirmations.
        ft.on_block_committed(5, hash(5), 5);
        assert_eq!(ft.confirmations_for_tip(), 2);
        assert_eq!(ft.finalized_height, 2);
    }

    #[test]
    fn test_restore_from_persistence() {
        let mut ft = FinalityTracker::new(3);
        ft.restore(10, hash(10), 20);
        assert_eq!(ft.finalized_height, 10);
        assert_eq!(ft.finalized_hash, hash(10));
        assert_eq!(ft.finalized_at_cycle, 20);
        assert_eq!(ft.status_for_height(5), FinalityStatus::Finalized);
        assert_eq!(ft.status_for_height(10), FinalityStatus::Finalized);
        assert_eq!(ft.status_for_height(11), FinalityStatus::Committed);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut ft = FinalityTracker::new(3);
        ft.on_block_committed(1, hash(1), 1);
        ft.on_block_committed(2, hash(2), 2);
        ft.on_block_committed(3, hash(3), 3);
        ft.on_block_committed(4, hash(4), 4);
        assert_eq!(ft.finalized_height, 1);

        ft.reset();
        // Ring buffer cleared but finalized_height preserved.
        assert_eq!(ft.finalized_height, 1);
        assert_eq!(ft.confirmations_for_tip(), 0);
        assert!(ft.cycle_commits.is_empty());

        // Full reset clears everything.
        ft.reset_full();
        assert_eq!(ft.finalized_height, 0);
    }
}
