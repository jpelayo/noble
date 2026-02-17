// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-IP token-bucket rate limiter for RPC request flood control.
//!
//! Each source IP gets an independent token bucket with configurable capacity
//! and refill rate. When a caller exhausts their tokens, the request is rejected.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// State of a single caller's token bucket.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Rate limiter tracking per-IP RPC request budgets.
pub struct RpcRateLimiter {
    inner: Mutex<RateLimiterInner>,
}

struct RateLimiterInner {
    buckets: HashMap<IpAddr, Bucket>,
    /// Maximum burst size (token bucket capacity).
    capacity: f64,
    /// Tokens refilled per second.
    rate: f64,
    /// Remove stale buckets after this duration of inactivity.
    stale_after: Duration,
    /// Maximum tracked IPs (evict oldest when exceeded).
    max_tracked: usize,
}

impl RpcRateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `requests_per_second`: sustained rate limit per IP.
    /// - `burst_multiplier`: burst = requests_per_second * multiplier.
    pub fn new(requests_per_second: u32, burst_multiplier: u32) -> Self {
        let capacity = (requests_per_second * burst_multiplier) as f64;
        Self {
            inner: Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                capacity,
                rate: requests_per_second as f64,
                stale_after: Duration::from_secs(300), // 5 min
                max_tracked: 10_000,
            }),
        }
    }

    /// Try to consume one token for the given IP address.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let capacity = inner.capacity;
        let rate = inner.rate;

        let bucket = inner.buckets.entry(ip).or_insert(Bucket {
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

    /// Remove stale entries (idle > 5 min) and evict oldest if over max_tracked.
    pub fn cleanup(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let stale_after = inner.stale_after;
        inner
            .buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < stale_after);

        // Evict oldest entries if we exceed the maximum tracked IPs
        let max = inner.max_tracked;
        if inner.buckets.len() > max {
            let mut entries: Vec<(IpAddr, Instant)> = inner
                .buckets
                .iter()
                .map(|(ip, b)| (*ip, b.last_refill))
                .collect();
            entries.sort_by_key(|&(_, t)| t);
            let to_remove = inner.buckets.len() - max;
            for (ip, _) in entries.into_iter().take(to_remove) {
                inner.buckets.remove(&ip);
            }
        }
    }

    /// Number of tracked IPs.
    pub fn tracked_ips(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .buckets
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn new_ip_gets_full_bucket() {
        let rl = RpcRateLimiter::new(10, 2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(rl.try_acquire(ip));
    }

    #[test]
    fn bucket_depletes_after_capacity() {
        let rl = RpcRateLimiter::new(1, 1); // capacity=1, rate=1/s
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(rl.try_acquire(ip)); // 1 → 0
        assert!(!rl.try_acquire(ip)); // depleted
    }

    #[test]
    fn bucket_refills_over_time() {
        let rl = RpcRateLimiter::new(100, 1); // 100 req/s, burst=100
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Deplete
        for _ in 0..100 {
            rl.try_acquire(ip);
        }
        assert!(!rl.try_acquire(ip));
        // Wait for refill (50ms at 100/s = ~5 tokens)
        thread::sleep(Duration::from_millis(50));
        assert!(rl.try_acquire(ip));
    }

    #[test]
    fn different_ips_tracked_independently() {
        let rl = RpcRateLimiter::new(1, 1); // capacity=1 per IP
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.try_acquire(ip1));
        assert!(rl.try_acquire(ip2));
        // Both depleted independently
        assert!(!rl.try_acquire(ip1));
        assert!(!rl.try_acquire(ip2));
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let rl = RpcRateLimiter::new(10, 2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        rl.try_acquire(ip);
        assert_eq!(rl.tracked_ips(), 1);

        // Override stale_after to a very short duration for testing
        {
            let mut inner = rl.inner.lock().unwrap();
            inner.stale_after = Duration::from_millis(10);
        }
        thread::sleep(Duration::from_millis(20));
        rl.cleanup();
        assert_eq!(rl.tracked_ips(), 0);
    }

    #[test]
    fn burst_allows_spikes() {
        let rl = RpcRateLimiter::new(10, 3); // capacity=30 (burst=3x), rate=10/s
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // Should allow 30 rapid requests (burst capacity)
        let mut allowed = 0;
        for _ in 0..35 {
            if rl.try_acquire(ip) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 30);
    }

    #[test]
    fn cleanup_evicts_oldest_when_over_max_tracked() {
        let rl = RpcRateLimiter::new(10, 2);
        // Set a small max_tracked
        {
            let mut inner = rl.inner.lock().unwrap();
            inner.max_tracked = 3;
        }
        // Add 5 IPs
        for i in 1..=5u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            rl.try_acquire(ip);
        }
        assert_eq!(rl.tracked_ips(), 5);

        // Cleanup should evict 2 oldest
        rl.cleanup();
        assert_eq!(rl.tracked_ips(), 3);
    }
}
