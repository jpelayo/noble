// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Signature verification cache — avoids re-verifying signatures for known transactions.
//!
//! Uses a simple LRU eviction strategy backed by a `LinkedHashMap`-style approach
//! with a `VecDeque` for insertion order.

use std::collections::{HashMap, VecDeque};

use noble_crypto::Hash256;

/// Default signature cache capacity (number of tx_ids).
pub const DEFAULT_SIG_CACHE_SIZE: usize = 10_000;

/// LRU cache of transaction IDs whose signatures have been verified.
///
/// When the cache is full, the oldest entry is evicted (FIFO, not true LRU
/// on access — this is fine because signature re-verification is cheap
/// relative to the benefit of avoiding it entirely).
pub struct SigCache {
    /// Set of cached tx_ids for O(1) lookup.
    entries: HashMap<Hash256, ()>,
    /// Insertion order for FIFO eviction.
    order: VecDeque<Hash256>,
    /// Maximum number of entries.
    capacity: usize,
    /// AUD-M3: Counter for inserts since last compaction.
    inserts_since_compact: usize,
}

impl SigCache {
    /// Create a new signature cache with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            inserts_since_compact: 0,
        }
    }

    /// Check if a tx_id's signatures have been previously verified.
    pub fn contains(&self, tx_id: &Hash256) -> bool {
        let hit = self.entries.contains_key(tx_id);
        if hit {
            tracing::trace!("sigcache hit for tx");
        }
        hit
    }

    /// Record that a tx_id's signatures have been verified.
    pub fn insert(&mut self, tx_id: Hash256) {
        if self.entries.contains_key(&tx_id) {
            return; // Already cached
        }

        // Evict oldest if at capacity, skipping phantom entries
        while self.entries.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) if self.entries.contains_key(&oldest) => {
                    self.entries.remove(&oldest);
                }
                Some(_) => continue, // phantom entry — already removed, skip
                None => break,
            }
        }

        tracing::trace!("sigcache miss, inserting");
        self.entries.insert(tx_id, ());
        self.order.push_back(tx_id);

        // AUD-M3: Compact phantom entries every 10,000 inserts
        self.inserts_since_compact += 1;
        if self.inserts_since_compact >= 10_000 {
            self.compact();
        }
    }

    /// AUD-M3: Rebuild the order deque, retaining only entries that are
    /// still present in the entries HashMap. This removes phantom entries
    /// left behind by `remove()` calls.
    pub fn compact(&mut self) {
        self.order.retain(|h| self.entries.contains_key(h));
        self.inserts_since_compact = 0;
    }

    /// Remove a specific entry (e.g., when a tx is confirmed or evicted).
    pub fn remove(&mut self, tx_id: &Hash256) {
        self.entries.remove(tx_id);
        // Note: we don't remove from `order` for performance — stale entries
        // are harmlessly skipped during eviction.
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

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::sha256;

    fn make_hash(i: u64) -> Hash256 {
        sha256(&i.to_be_bytes())
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = SigCache::new(100);
        let h = make_hash(1);
        assert!(!cache.contains(&h));
        cache.insert(h);
        assert!(cache.contains(&h));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn duplicate_insert_is_noop() {
        let mut cache = SigCache::new(100);
        let h = make_hash(1);
        cache.insert(h);
        cache.insert(h);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eviction_at_capacity() {
        let mut cache = SigCache::new(3);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);
        let h4 = make_hash(4);

        cache.insert(h1);
        cache.insert(h2);
        cache.insert(h3);
        assert_eq!(cache.len(), 3);

        // Inserting h4 should evict h1 (oldest)
        cache.insert(h4);
        assert_eq!(cache.len(), 3);
        assert!(!cache.contains(&h1));
        assert!(cache.contains(&h2));
        assert!(cache.contains(&h3));
        assert!(cache.contains(&h4));
    }

    #[test]
    fn explicit_remove() {
        let mut cache = SigCache::new(100);
        let h = make_hash(1);
        cache.insert(h);
        cache.remove(&h);
        assert!(!cache.contains(&h));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn empty_cache() {
        let cache = SigCache::new(10);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    // AUD-M3: Phantom compaction removes stale order entries
    #[test]
    fn compact_removes_phantoms() {
        let mut cache = SigCache::new(100);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);

        cache.insert(h1);
        cache.insert(h2);
        cache.insert(h3);
        assert_eq!(cache.order.len(), 3);

        // Remove h1 and h2 (creates phantoms in order)
        cache.remove(&h1);
        cache.remove(&h2);
        assert_eq!(cache.len(), 1); // only h3
        assert_eq!(cache.order.len(), 3); // phantoms still in order

        // Compact should remove phantoms
        cache.compact();
        assert_eq!(cache.order.len(), 1); // only h3 remains
        assert!(cache.contains(&h3));
    }

    // AUD-M3: Compaction preserves all valid entries
    #[test]
    fn compact_preserves_valid_entries() {
        let mut cache = SigCache::new(100);
        for i in 0..50u64 {
            cache.insert(make_hash(i));
        }
        // Remove every other entry
        for i in (0..50u64).step_by(2) {
            cache.remove(&make_hash(i));
        }
        assert_eq!(cache.len(), 25);
        assert_eq!(cache.order.len(), 50); // 25 phantoms

        cache.compact();
        assert_eq!(cache.len(), 25);
        assert_eq!(cache.order.len(), 25); // phantoms removed
                                           // Verify all odd entries still present
        for i in (1..50u64).step_by(2) {
            assert!(cache.contains(&make_hash(i)));
        }
    }

    #[test]
    fn phantom_entries_skipped_on_eviction() {
        // Capacity 2: insert h1, h2, remove h1 (phantom), insert h3, insert h4
        let mut cache = SigCache::new(2);
        let h1 = make_hash(1);
        let h2 = make_hash(2);
        let h3 = make_hash(3);
        let h4 = make_hash(4);

        cache.insert(h1);
        cache.insert(h2);
        assert_eq!(cache.len(), 2);

        // Remove h1 explicitly (creates phantom in order deque)
        cache.remove(&h1);
        assert_eq!(cache.len(), 1); // only h2

        // Insert h3 — no eviction needed (len=1 < capacity=2)
        cache.insert(h3);
        assert_eq!(cache.len(), 2); // h2, h3

        // Insert h4 — needs eviction. order is [h1(phantom), h2, h3].
        // Should skip phantom h1, then evict h2.
        cache.insert(h4);
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&h1));
        assert!(
            !cache.contains(&h2),
            "h2 should be evicted after phantom skip"
        );
        assert!(cache.contains(&h3));
        assert!(cache.contains(&h4));
    }
}
