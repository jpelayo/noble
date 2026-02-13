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

/// Rate limiter tracking per-peer transaction relay budgets.
pub struct TxRateLimiter {
    buckets: HashMap<PeerId, Bucket>,
    capacity: f64,
    rate: f64,
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
        }
    }

    /// Try to consume one token for the given peer.
    ///
    /// Returns `true` if the relay is allowed, `false` if rate-limited.
    pub fn try_consume(&mut self, peer_id: &PeerId) -> bool {
        let now = Instant::now();
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

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.buckets.len()
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
