// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Connection diversity utilities for subnet-aware peer selection.
//!
//! Prevents eclipse attacks by limiting outbound connections to the same /16 subnet
//! and providing quality scoring for peer rotation.

use std::time::Duration;

use crate::peer_manager::PeerState;

/// Default maximum outbound connections per /16 subnet.
pub const MAX_PER_SUBNET: usize = 2;

/// Extract the /16 subnet identifier from a multiaddr string.
///
/// Parses the first IPv4 address component and returns the first two octets
/// packed as a `u16`. Returns `None` for non-IPv4 addresses.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(extract_subnet("/ip4/192.168.1.5/tcp/9333"), Some(0xC0A8)); // 192.168
/// assert_eq!(extract_subnet("/ip6/::1/tcp/9333"), None);
/// ```
pub fn extract_subnet(addr: &str) -> Option<u16> {
    // Look for "/ip4/x.x.x.x" pattern.
    let parts: Vec<&str> = addr.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "ip4" {
            if let Some(ip_str) = parts.get(i + 1) {
                let octets: Vec<u8> = ip_str
                    .split('.')
                    .filter_map(|o| o.parse::<u8>().ok())
                    .collect();
                if octets.len() == 4 {
                    return Some(((octets[0] as u16) << 8) | (octets[1] as u16));
                }
            }
        }
    }
    None
}

/// Compute a quality score for a peer (lower is better).
///
/// Factors:
/// - Latency: higher latency → higher (worse) score
/// - Ban score: higher ban score → higher (worse) score
/// - Uptime: longer connection → lower (better) score
pub fn peer_quality_score(state: &PeerState) -> f64 {
    let latency_ms = state
        .latency
        .unwrap_or(Duration::from_millis(500))
        .as_millis() as f64;

    let ban_penalty = state.ban_score as f64 * 10.0;

    let uptime_secs = state.connected_at.elapsed().as_secs_f64();
    // Longer uptime is rewarded (subtracted from score), capped at 3600s.
    let uptime_bonus = uptime_secs.min(3600.0);

    latency_ms + ban_penalty - uptime_bonus
}

/// Check whether adding a new outbound connection to `candidate_addr`
/// would violate the per-subnet diversity limit.
///
/// Returns `true` if the connection is allowed, `false` if it would exceed
/// `max_per_subnet` outbound connections to the same /16 subnet.
pub fn check_subnet_diversity(
    existing_addrs: &[String],
    candidate_addr: &str,
    max_per_subnet: usize,
) -> bool {
    let candidate_subnet = match extract_subnet(candidate_addr) {
        Some(s) => s,
        None => return true, // Non-IPv4 — allow by default.
    };

    let same_subnet_count = existing_addrs
        .iter()
        .filter(|a| extract_subnet(a) == Some(candidate_subnet))
        .count();

    same_subnet_count < max_per_subnet
}

/// Find the worst-quality outbound peer from the given set.
///
/// Returns the index and score of the peer with the highest (worst) quality score,
/// or `None` if the list is empty.
pub fn worst_outbound_peer(peers: &[(&str, &PeerState)]) -> Option<(usize, f64)> {
    peers
        .iter()
        .enumerate()
        .map(|(i, (_, state))| (i, peer_quality_score(state)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::Direction;
    use std::time::Instant;

    fn make_peer_state(latency_ms: u64, ban_score: u32) -> PeerState {
        PeerState {
            direction: Direction::Outbound,
            ban_score,
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            chain_tip: None,
            latency: Some(Duration::from_millis(latency_ms)),
            announce: None,
            addr: None,
        }
    }

    #[test]
    fn extract_subnet_ipv4() {
        assert_eq!(
            extract_subnet("/ip4/192.168.1.5/tcp/9333"),
            Some(0xC0A8) // 192 << 8 | 168
        );
        assert_eq!(
            extract_subnet("/ip4/10.0.42.1/tcp/9333"),
            Some(0x0A00) // 10 << 8 | 0
        );
    }

    #[test]
    fn extract_subnet_non_ip_returns_none() {
        assert_eq!(extract_subnet("/ip6/::1/tcp/9333"), None);
        assert_eq!(extract_subnet("/dns4/example.com/tcp/9333"), None);
    }

    #[test]
    fn quality_score_higher_latency_worse() {
        let fast = make_peer_state(10, 0);
        let slow = make_peer_state(500, 0);
        assert!(peer_quality_score(&fast) < peer_quality_score(&slow));
    }

    #[test]
    fn quality_score_higher_ban_score_worse() {
        let good = make_peer_state(50, 0);
        let bad = make_peer_state(50, 30);
        assert!(peer_quality_score(&good) < peer_quality_score(&bad));
    }

    #[test]
    fn diversity_allows_first_connection() {
        let existing: Vec<String> = vec![];
        assert!(check_subnet_diversity(
            &existing,
            "/ip4/192.168.1.1/tcp/9333",
            2
        ));
    }

    #[test]
    fn diversity_blocks_over_limit() {
        let existing = vec![
            "/ip4/192.168.1.1/tcp/9333".to_string(),
            "/ip4/192.168.2.2/tcp/9333".to_string(),
        ];
        // Same /16 subnet (192.168.x.x) — should be blocked at max=2.
        assert!(!check_subnet_diversity(
            &existing,
            "/ip4/192.168.3.3/tcp/9333",
            2
        ));
    }

    #[test]
    fn diversity_allows_different_subnet() {
        let existing = vec![
            "/ip4/192.168.1.1/tcp/9333".to_string(),
            "/ip4/192.168.2.2/tcp/9333".to_string(),
        ];
        // Different /16 subnet (10.0.x.x) — should be allowed.
        assert!(check_subnet_diversity(
            &existing,
            "/ip4/10.0.1.1/tcp/9333",
            2
        ));
    }

    #[test]
    fn worst_outbound_peer_selects_highest_score() {
        let state1 = make_peer_state(10, 0);
        let state2 = make_peer_state(500, 50);
        let peers = vec![
            ("/ip4/1.2.3.4/tcp/9333", &state1),
            ("/ip4/5.6.7.8/tcp/9333", &state2),
        ];
        let (idx, _score) = worst_outbound_peer(&peers).unwrap();
        assert_eq!(idx, 1); // state2 is worse (higher latency + ban score)
    }
}
