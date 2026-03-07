// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Periodic checkpoint system for reorg protection.
//!
//! Creates block anchors at fixed height intervals. After an activation
//! delay, active checkpoints act as a reorg floor — `reset_tip()` cannot
//! go below the highest active checkpoint.

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// A single checkpoint record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: Hash256,
    pub created_at_cycle: u64,
    pub activates_at_cycle: u64,
    pub active: bool,
}

/// Manages periodic block checkpoints.
pub struct CheckpointManager {
    /// Create a checkpoint every N blocks (0 = disabled).
    interval: u64,
    /// Cycles after creation before activation.
    activation_delay: u32,
    /// All known checkpoints (ordered by height).
    checkpoints: Vec<Checkpoint>,
    /// Cached reorg floor (highest active checkpoint height).
    highest_active_height: u64,
}

impl CheckpointManager {
    pub fn new(interval: u64, activation_delay: u32) -> Self {
        Self {
            interval,
            activation_delay,
            checkpoints: Vec::new(),
            highest_active_height: 0,
        }
    }

    /// Whether a checkpoint should be created at this height.
    pub fn should_checkpoint(&self, height: u64) -> bool {
        height > 0 && self.interval > 0 && height % self.interval == 0
    }

    /// Called when a block is committed.  Returns the new checkpoint if one
    /// was created at this height.
    pub fn on_block_committed(
        &mut self,
        height: u64,
        hash: Hash256,
        cycle: u64,
    ) -> Option<Checkpoint> {
        if !self.should_checkpoint(height) {
            return None;
        }

        // No duplicate checkpoints for the same height.
        if self.checkpoints.iter().any(|cp| cp.height == height) {
            return None;
        }

        let activates_at = cycle + self.activation_delay as u64;
        let active = self.activation_delay == 0;

        let cp = Checkpoint {
            height,
            hash,
            created_at_cycle: cycle,
            activates_at_cycle: activates_at,
            active,
        };

        self.checkpoints.push(cp.clone());
        self.checkpoints.sort_by_key(|c| c.height);

        if active && height > self.highest_active_height {
            self.highest_active_height = height;
        }

        Some(cp)
    }

    /// Activate pending checkpoints whose activation cycle has arrived.
    /// Returns heights of newly activated checkpoints.
    pub fn tick_activation(&mut self, current_cycle: u64) -> Vec<u64> {
        let mut activated = Vec::new();
        for cp in &mut self.checkpoints {
            if !cp.active && current_cycle >= cp.activates_at_cycle {
                cp.active = true;
                activated.push(cp.height);
                if cp.height > self.highest_active_height {
                    self.highest_active_height = cp.height;
                }
            }
        }
        activated
    }

    /// Highest active checkpoint height (reorg floor).
    pub fn highest_active_height(&self) -> u64 {
        self.highest_active_height
    }

    /// Get the checkpoint interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Recent checkpoints, most recent first.
    pub fn recent_checkpoints(&self, limit: usize) -> Vec<&Checkpoint> {
        self.checkpoints.iter().rev().take(limit).collect()
    }

    /// Total number of checkpoints.
    pub fn total(&self) -> usize {
        self.checkpoints.len()
    }

    /// Restore checkpoints from storage on startup.
    pub fn restore(&mut self, checkpoints: Vec<Checkpoint>) {
        self.checkpoints = checkpoints;
        self.checkpoints.sort_by_key(|c| c.height);
        self.highest_active_height = self
            .checkpoints
            .iter()
            .filter(|c| c.active)
            .map(|c| c.height)
            .max()
            .unwrap_or(0);
    }

    /// Full reset (used for blockchain hop / chain reset).
    pub fn reset(&mut self) {
        self.checkpoints.clear();
        self.highest_active_height = 0;
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
    fn checkpoint_at_interval() {
        let mut mgr = CheckpointManager::new(30, 3);
        let cp = mgr.on_block_committed(30, hash(30), 10);
        assert!(cp.is_some());
        let cp = cp.unwrap();
        assert_eq!(cp.height, 30);
        assert_eq!(cp.created_at_cycle, 10);
        assert_eq!(cp.activates_at_cycle, 13);
        assert!(!cp.active);
    }

    #[test]
    fn no_checkpoint_between_intervals() {
        let mut mgr = CheckpointManager::new(30, 3);
        assert!(mgr.on_block_committed(15, hash(15), 5).is_none());
        assert!(mgr.on_block_committed(29, hash(29), 9).is_none());
        assert!(mgr.on_block_committed(31, hash(31), 11).is_none());
    }

    #[test]
    fn activation_delay() {
        let mut mgr = CheckpointManager::new(30, 3);
        mgr.on_block_committed(30, hash(30), 10);
        assert_eq!(mgr.highest_active_height(), 0);

        // Cycle 12 — not yet
        let activated = mgr.tick_activation(12);
        assert!(activated.is_empty());
        assert_eq!(mgr.highest_active_height(), 0);

        // Cycle 13 — activates
        let activated = mgr.tick_activation(13);
        assert_eq!(activated, vec![30]);
        assert_eq!(mgr.highest_active_height(), 30);
    }

    #[test]
    fn zero_activation_delay() {
        let mut mgr = CheckpointManager::new(30, 0);
        let cp = mgr.on_block_committed(30, hash(30), 10);
        assert!(cp.unwrap().active);
        assert_eq!(mgr.highest_active_height(), 30);
    }

    #[test]
    fn highest_active_height_tracks() {
        let mut mgr = CheckpointManager::new(10, 0);
        mgr.on_block_committed(10, hash(10), 1);
        assert_eq!(mgr.highest_active_height(), 10);
        mgr.on_block_committed(20, hash(20), 2);
        assert_eq!(mgr.highest_active_height(), 20);
        mgr.on_block_committed(30, hash(30), 3);
        assert_eq!(mgr.highest_active_height(), 30);
    }

    #[test]
    fn no_duplicate_checkpoints() {
        let mut mgr = CheckpointManager::new(30, 3);
        let cp1 = mgr.on_block_committed(30, hash(30), 10);
        assert!(cp1.is_some());
        let cp2 = mgr.on_block_committed(30, hash(31), 11);
        assert!(cp2.is_none());
        assert_eq!(mgr.total(), 1);
    }

    #[test]
    fn restore_from_storage() {
        let mut mgr = CheckpointManager::new(30, 3);
        let saved = vec![
            Checkpoint {
                height: 30,
                hash: hash(30),
                created_at_cycle: 10,
                activates_at_cycle: 13,
                active: true,
            },
            Checkpoint {
                height: 60,
                hash: hash(60),
                created_at_cycle: 20,
                activates_at_cycle: 23,
                active: false,
            },
        ];
        mgr.restore(saved);
        assert_eq!(mgr.total(), 2);
        assert_eq!(mgr.highest_active_height(), 30);
    }

    #[test]
    fn reset_clears_all() {
        let mut mgr = CheckpointManager::new(10, 0);
        mgr.on_block_committed(10, hash(10), 1);
        mgr.on_block_committed(20, hash(20), 2);
        assert_eq!(mgr.total(), 2);
        assert_eq!(mgr.highest_active_height(), 20);

        mgr.reset();
        assert_eq!(mgr.total(), 0);
        assert_eq!(mgr.highest_active_height(), 0);
    }

    #[test]
    fn height_zero_skipped() {
        let mut mgr = CheckpointManager::new(1, 0);
        assert!(mgr.on_block_committed(0, hash(0), 0).is_none());
    }

    #[test]
    fn recent_checkpoints_ordering() {
        let mut mgr = CheckpointManager::new(10, 0);
        mgr.on_block_committed(10, hash(10), 1);
        mgr.on_block_committed(20, hash(20), 2);
        mgr.on_block_committed(30, hash(30), 3);

        let recent: Vec<u64> = mgr.recent_checkpoints(2).iter().map(|c| c.height).collect();
        assert_eq!(recent, vec![30, 20]);
    }
}
