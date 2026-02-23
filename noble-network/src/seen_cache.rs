// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! TTL-based deduplication cache for gossip messages.
//!
//! Used to suppress re-processing of already-seen blocks, transactions, and votes.
//! Each entry has a time-to-live; expired entries are evicted on demand.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// A cache that remembers recently-seen items by their 32-byte key.
///
/// Items expire after `ttl` and can be bulk-evicted with [`evict_expired`].
/// The cache also enforces a `max_entries` cap — oldest entries are dropped
/// in O(1) via an insertion-order queue when the cap is exceeded.
pub struct SeenCache {
    entries: HashMap<[u8; 32], Instant>,
    /// Insertion-order queue for O(1) oldest eviction (replaces O(n) min_by_key scan).
    insertion_order: VecDeque<[u8; 32]>,
    ttl: Duration,
    max_entries: usize,
}

impl SeenCache {
    /// Create a new `SeenCache` with the given TTL and maximum entry count.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            ttl,
            max_entries,
        }
    }

    /// Insert a key if it has not been seen recently.
    ///
    /// Returns `true` if the key is **new** (not seen before or expired).
    /// Returns `false` if the key was already present and still live.
    pub fn insert_if_new(&mut self, key: [u8; 32]) -> bool {
        let now = Instant::now();

        // Check if already present and still live.
        if let Some(inserted_at) = self.entries.get(&key) {
            if now.duration_since(*inserted_at) < self.ttl {
                tracing::trace!(task = "seen_cache", "cache hit: message already seen");
                return false;
            }
        }

        // Enforce max_entries cap by evicting expired first.
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }

        // If still at cap after eviction, drop the oldest entry via O(1) front pop.
        while self.entries.len() >= self.max_entries {
            if let Some(oldest_key) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest_key);
            } else {
                break;
            }
        }

        self.entries.insert(key, now);
        self.insertion_order.push_back(key);
        tracing::trace!(task = "seen_cache", "cache insert, size: {}", self.len());
        true
    }

    /// Remove all expired entries. Returns the number of entries evicted.
    pub fn evict_expired(&mut self) -> usize {
        let before = self.entries.len();
        let ttl = self.ttl;
        self.entries
            .retain(|_, inserted_at| inserted_at.elapsed() < ttl);
        let evicted = before - self.entries.len();
        if evicted > 0 {
            // Rebuild insertion_order to remove evicted keys.
            self.insertion_order
                .retain(|k| self.entries.contains_key(k));
        }
        evicted
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute a deterministic dedup key for a PoR vote.
///
/// The key is `SHA-256(cycle_le_bytes || voter_id_bytes || round)`, ensuring that
/// the same voter voting in the same cycle and round always produces the same key.
/// Different rounds produce distinct keys so R2 votes are not suppressed as R1 duplicates.
pub fn vote_dedup_key(cycle: u64, voter_id: &[u8], round: u8) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cycle.to_le_bytes());
    hasher.update(voter_id);
    hasher.update([round]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn insert_new_returns_true() {
        let mut cache = SeenCache::new(Duration::from_secs(60), 100);
        assert!(cache.insert_if_new([1; 32]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insert_duplicate_returns_false() {
        let mut cache = SeenCache::new(Duration::from_secs(60), 100);
        assert!(cache.insert_if_new([1; 32]));
        assert!(!cache.insert_if_new([1; 32]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn different_keys_both_new() {
        let mut cache = SeenCache::new(Duration::from_secs(60), 100);
        assert!(cache.insert_if_new([1; 32]));
        assert!(cache.insert_if_new([2; 32]));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn expired_entry_treated_as_new() {
        let mut cache = SeenCache::new(Duration::from_millis(10), 100);
        assert!(cache.insert_if_new([1; 32]));
        thread::sleep(Duration::from_millis(20));
        // After TTL, same key should be treated as new.
        assert!(cache.insert_if_new([1; 32]));
    }

    #[test]
    fn evict_expired_removes_old_entries() {
        let mut cache = SeenCache::new(Duration::from_millis(10), 100);
        cache.insert_if_new([1; 32]);
        cache.insert_if_new([2; 32]);
        thread::sleep(Duration::from_millis(20));
        let evicted = cache.evict_expired();
        assert_eq!(evicted, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn max_entries_cap_drops_oldest() {
        let mut cache = SeenCache::new(Duration::from_secs(60), 2);
        cache.insert_if_new([1; 32]);
        cache.insert_if_new([2; 32]);
        // Third insert should evict oldest.
        cache.insert_if_new([3; 32]);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn vote_dedup_key_deterministic() {
        let key1 = vote_dedup_key(5, &[1, 2, 3], 1);
        let key2 = vote_dedup_key(5, &[1, 2, 3], 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn vote_dedup_key_different_cycle() {
        let key1 = vote_dedup_key(5, &[1, 2, 3], 1);
        let key2 = vote_dedup_key(6, &[1, 2, 3], 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn vote_dedup_key_different_voter() {
        let key1 = vote_dedup_key(5, &[1, 2, 3], 1);
        let key2 = vote_dedup_key(5, &[4, 5, 6], 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn vote_dedup_key_different_round() {
        let key1 = vote_dedup_key(5, &[1, 2, 3], 1);
        let key2 = vote_dedup_key(5, &[1, 2, 3], 2);
        assert_ne!(
            key1, key2,
            "same cycle+voter but different round must produce different keys"
        );
    }
}
