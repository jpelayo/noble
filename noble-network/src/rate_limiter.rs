// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-peer token-bucket rate limiter for transaction relay flood control.
//!
//! Each peer gets an independent token bucket with configurable capacity and
//! refill rate. When a peer exhausts their tokens, further transaction relay
//! is suppressed, and sustained flooding triggers a `TxFlood` misbehavior report.

use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;

/// State of a single peer's token bucket.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Hard cap on the number of tracked peers. In practice the map is already
/// bounded by the connection limit — only connected gossip sources get a bucket
/// and `remove_peer` runs on disconnect — so this is belt-and-suspenders against
/// a missed removal or a future change, mirroring the API limiter's `max_tracked`.
const MAX_TRACKED_PEERS: usize = 4096;

/// Rate limiter tracking per-peer transaction relay budgets.
pub struct TxRateLimiter {
    buckets: HashMap<PeerId, Bucket>,
    capacity: f64,
    rate: f64,
    /// Upper bound on `buckets`; the least-recently-active entry is evicted when
    /// a new peer would exceed it.
    max_tracked: usize,
}

impl TxRateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `capacity`: maximum burst size (token bucket capacity).
    /// - `rate`: tokens refilled per second.
    pub fn new(capacity: u32, rate: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity: capacity as f64,
            rate: rate as f64,
            max_tracked: MAX_TRACKED_PEERS,
        }
    }

    /// Try to consume one token for the given peer.
    ///
    /// Returns `true` if the relay is allowed, `false` if rate-limited.
    pub fn try_consume(&mut self, peer_id: &PeerId) -> bool {
        let now = Instant::now();
        // Bound the map at all times: when a NEW peer would exceed the cap,
        // evict the least-recently-active bucket first.
        if self.buckets.len() >= self.max_tracked && !self.buckets.contains_key(peer_id) {
            self.evict_oldest();
        }
        let capacity = self.capacity;
        let rate = self.rate;

        let bucket = self.buckets.entry(*peer_id).or_insert(Bucket {
            tokens: capacity,
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove a peer's bucket (on disconnect).
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.buckets.remove(peer_id);
    }

    /// Remove buckets for peers that have been idle longer than `max_idle`.
    pub fn cleanup(&mut self, max_idle: std::time::Duration) {
        self.buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < max_idle);
    }

    /// Evict the least-recently-active bucket (enforces `max_tracked`).
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last_refill)
            .map(|(p, _)| *p)
        {
            self.buckets.remove(&oldest);
        }
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.buckets.len()
    }
}

// ---------------------------------------------------------------------------
// K3-05: weighted ingress budgets with a reserved consensus pool
// ---------------------------------------------------------------------------

/// Gossip topic classes for ingress accounting (K3-05). Costs reflect the
/// expected decode + signature-verification + routing work, not message count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressTopic {
    TxAnnounce,
    BlockAnnounce,
    Vote,
    Evidence,
    NodeAnnounce,
    PeerExchange,
}

impl IngressTopic {
    /// Weighted cost in budget units (tunable here — one place).
    pub fn cost(self) -> f64 {
        match self {
            IngressTopic::TxAnnounce => 1.0,
            IngressTopic::BlockAnnounce => 2.0,
            IngressTopic::Vote => 1.0,
            IngressTopic::Evidence => 4.0,
            IngressTopic::NodeAnnounce => 4.0,
            IngressTopic::PeerExchange => 8.0,
        }
    }

    /// Consensus-critical topics draw from their OWN reserved global pool so
    /// tx/announce/PeX floods can never starve votes, blocks, or evidence.
    pub fn is_consensus(self) -> bool {
        matches!(
            self,
            IngressTopic::Vote | IngressTopic::BlockAnnounce | IngressTopic::Evidence
        )
    }
}

/// A single weighted token bucket.
struct GlobalBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last_refill: Instant,
}

impl GlobalBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        Self { tokens: capacity, capacity, rate, last_refill: Instant::now() }
    }
    fn try_consume(&mut self, cost: f64, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Two-level weighted ingress budget (K3-05):
///
/// 1. **Per-peer** weighted bucket — one peer cannot flood any topic.
/// 2. **Global** buckets with a RESERVED consensus pool — consensus topics
///    (votes/blocks/evidence) have independent capacity, so flooding any
///    non-consensus topic leaves a tested minimum of consensus throughput.
///
/// Checked BEFORE decode and signature verification (the caller maps the
/// gossipsub topic id to an [`IngressTopic`] without touching the payload).
pub struct IngressBudget {
    /// Per-peer weighted buckets (all topics share one bucket per peer; the
    /// COST differs per topic). Reuses the bounded LRU discipline.
    per_peer: TxRateLimiter,
    /// Reserved pool for consensus-critical topics.
    global_consensus: GlobalBucket,
    /// Pool for everything else.
    global_general: GlobalBucket,
    /// Drop counters per topic (bounded, observable via periodic log).
    pub dropped: [u64; 6],
}

impl IngressBudget {
    /// `peer_burst`/`peer_rate`: weighted units per peer (burst / per-second).
    /// `consensus_burst`/`consensus_rate` and `general_burst`/`general_rate`:
    /// the two global pools.
    pub fn new(
        peer_burst: u32,
        peer_rate: u32,
        consensus_burst: u32,
        consensus_rate: u32,
        general_burst: u32,
        general_rate: u32,
    ) -> Self {
        Self {
            per_peer: TxRateLimiter::new(peer_burst, peer_rate),
            global_consensus: GlobalBucket::new(consensus_burst as f64, consensus_rate as f64),
            global_general: GlobalBucket::new(general_burst as f64, general_rate as f64),
            dropped: [0; 6],
        }
    }

    fn topic_index(topic: IngressTopic) -> usize {
        match topic {
            IngressTopic::TxAnnounce => 0,
            IngressTopic::BlockAnnounce => 1,
            IngressTopic::Vote => 2,
            IngressTopic::Evidence => 3,
            IngressTopic::NodeAnnounce => 4,
            IngressTopic::PeerExchange => 5,
        }
    }

    /// Charge `topic`'s cost for a message relayed by `peer`.
    /// Returns `false` (drop before decode) when either the peer's or the
    /// applicable global budget is exhausted.
    pub fn try_consume(&mut self, peer: &PeerId, topic: IngressTopic) -> bool {
        let cost = topic.cost();
        let now = Instant::now();
        // Per-peer first (weighted: charge `cost` tokens).
        if !self.per_peer.try_consume_weighted(peer, cost) {
            self.dropped[Self::topic_index(topic)] += 1;
            return false;
        }
        let pool = if topic.is_consensus() {
            &mut self.global_consensus
        } else {
            &mut self.global_general
        };
        if !pool.try_consume(cost, now) {
            self.dropped[Self::topic_index(topic)] += 1;
            return false;
        }
        true
    }

    /// Remove a peer's bucket (on disconnect).
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.per_peer.remove_peer(peer_id);
    }

    /// Drop idle per-peer buckets.
    pub fn cleanup(&mut self, max_idle: std::time::Duration) {
        self.per_peer.cleanup(max_idle);
    }

    /// Total drops across all topics (for periodic observability logging).
    pub fn total_dropped(&self) -> u64 {
        self.dropped.iter().sum()
    }
}

impl TxRateLimiter {
    /// Weighted variant of [`TxRateLimiter::try_consume`]: charge `cost`
    /// tokens instead of exactly one.
    pub fn try_consume_weighted(&mut self, peer_id: &PeerId, cost: f64) -> bool {
        let now = Instant::now();
        if self.buckets.len() >= self.max_tracked && !self.buckets.contains_key(peer_id) {
            self.evict_oldest();
        }
        let capacity = self.capacity;
        let rate = self.rate;
        let bucket = self.buckets.entry(*peer_id).or_insert(Bucket {
            tokens: capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);
        bucket.last_refill = now;
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod ingress_tests {
    use super::*;

    #[test]
    fn consensus_pool_survives_general_flood() {
        // Tiny general pool, independent consensus pool.
        let mut b = IngressBudget::new(1000, 1000, 100, 0, 10, 0);
        let flooder = PeerId::random();
        // Exhaust the general pool with PeX (cost 8) + NodeAnnounce (cost 4).
        assert!(b.try_consume(&flooder, IngressTopic::PeerExchange)); // 10-8=2
        assert!(!b.try_consume(&flooder, IngressTopic::NodeAnnounce)); // needs 4 > 2
        // Consensus topics still flow from their reserved pool.
        for _ in 0..50 {
            assert!(b.try_consume(&flooder, IngressTopic::Vote), "votes must never starve");
        }
        assert!(b.try_consume(&flooder, IngressTopic::BlockAnnounce));
        assert!(b.total_dropped() >= 1);
    }

    #[test]
    fn per_peer_budget_is_weighted_and_independent() {
        // Per-peer burst 8, no refill: one PeX (8) exhausts a peer.
        let mut b = IngressBudget::new(8, 0, 1000, 1000, 1000, 1000);
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        assert!(b.try_consume(&p1, IngressTopic::PeerExchange)); // 8-8=0
        assert!(!b.try_consume(&p1, IngressTopic::Vote), "peer budget exhausted");
        assert!(b.try_consume(&p2, IngressTopic::Vote), "other peers unaffected");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn new_peer_gets_full_bucket() {
        let mut rl = TxRateLimiter::new(10, 10);
        let peer = PeerId::random();
        // First consume should always succeed.
        assert!(rl.try_consume(&peer));
    }

    #[test]
    fn bucket_depletes_after_capacity() {
        let mut rl = TxRateLimiter::new(3, 0);
        let peer = PeerId::random();
        assert!(rl.try_consume(&peer)); // 3 -> 2
        assert!(rl.try_consume(&peer)); // 2 -> 1
        assert!(rl.try_consume(&peer)); // 1 -> 0
        assert!(!rl.try_consume(&peer)); // depleted
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut rl = TxRateLimiter::new(3, 1000);
        let peer = PeerId::random();
        // Deplete.
        rl.try_consume(&peer);
        rl.try_consume(&peer);
        rl.try_consume(&peer);
        assert!(!rl.try_consume(&peer));

        // Wait for refill.
        thread::sleep(Duration::from_millis(20));
        assert!(rl.try_consume(&peer));
    }

    #[test]
    fn remove_peer_clears_bucket() {
        let mut rl = TxRateLimiter::new(10, 10);
        let peer = PeerId::random();
        rl.try_consume(&peer);
        assert_eq!(rl.peer_count(), 1);
        rl.remove_peer(&peer);
        assert_eq!(rl.peer_count(), 0);
    }

    #[test]
    fn cleanup_removes_stale_buckets() {
        let mut rl = TxRateLimiter::new(10, 10);
        let peer = PeerId::random();
        rl.try_consume(&peer);
        thread::sleep(Duration::from_millis(20));
        rl.cleanup(Duration::from_millis(10));
        assert_eq!(rl.peer_count(), 0);
    }

    #[test]
    fn evicts_oldest_when_over_max_tracked() {
        let mut rl = TxRateLimiter::new(10, 10);
        rl.max_tracked = 2;
        rl.try_consume(&PeerId::random());
        rl.try_consume(&PeerId::random());
        rl.try_consume(&PeerId::random()); // 3rd new peer → evict oldest first
        assert!(rl.peer_count() <= 2, "map must stay bounded by max_tracked");
    }

    #[test]
    fn independent_buckets_per_peer() {
        let mut rl = TxRateLimiter::new(1, 0);
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        assert!(rl.try_consume(&p1));
        assert!(rl.try_consume(&p2));
        // Both depleted independently.
        assert!(!rl.try_consume(&p1));
        assert!(!rl.try_consume(&p2));
    }
}
