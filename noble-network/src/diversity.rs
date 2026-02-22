// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Connection diversity utilities for subnet-aware peer selection.
//!
//! Prevents eclipse attacks by limiting outbound connections to the same /16 subnet
//! (IPv4) or /48 prefix (IPv6) and providing quality scoring for peer rotation.

use std::time::Duration;

use crate::peer_manager::PeerState;

/// Default maximum outbound connections per /16 subnet (IPv4) or /48 prefix (IPv6).
pub const MAX_PER_SUBNET: usize = 2;

/// Subnet identifier for diversity tracking.
///
/// IPv4 uses the /16 prefix (first two octets); IPv6 uses the /48 prefix
/// (first three 16-bit groups). Both are packed into compact value types
/// that implement `PartialEq` for efficient comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubnetId {
    /// IPv4 /16 prefix, encoded as `(first_octet << 8) | second_octet`.
    V4(u16),
    /// IPv6 /48 prefix, encoded as the first three 16-bit groups.
    V6(u16, u16, u16),
}

/// Extract the subnet identifier from a multiaddr string.
///
/// - For `/ip4/x.x.x.x/…` returns `SubnetId::V4` (first two octets).
/// - For `/ip6/…/…` returns `SubnetId::V6` (first three 16-bit groups, /48 prefix).
/// - Returns `None` for DNS or unknown address families.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(extract_subnet("/ip4/192.168.1.5/tcp/8780"), Some(SubnetId::V4(0xC0A8)));
/// assert_eq!(extract_subnet("/ip6/2001:db8:1::1/tcp/8780"), Some(SubnetId::V6(0x2001, 0x0db8, 0x0001)));
/// assert_eq!(extract_subnet("/dns4/example.com/tcp/8780"), None);
/// ```
pub fn extract_subnet(addr: &str) -> Option<SubnetId> {
    let parts: Vec<&str> = addr.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "ip4" {
            if let Some(ip_str) = parts.get(i + 1) {
                let octets: Vec<u8> = ip_str
                    .split('.')
                    .filter_map(|o| o.parse::<u8>().ok())
                    .collect();
                if octets.len() == 4 {
                    return Some(SubnetId::V4(((octets[0] as u16) << 8) | (octets[1] as u16)));
                }
            }
        } else if *part == "ip6" {
            if let Some(ip_str) = parts.get(i + 1) {
                // Parse full IPv6 address (handles compressed forms like ::1)
                // and extract the /48 prefix (first three 16-bit groups).
                if let Ok(ip6) = ip_str.parse::<std::net::Ipv6Addr>() {
                    let segs = ip6.segments();
                    return Some(SubnetId::V6(segs[0], segs[1], segs[2]));
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
/// `max_per_subnet` outbound connections to the same subnet.
/// Non-IP addresses (DNS) are allowed by default.
pub fn check_subnet_diversity(
    existing_addrs: &[String],
    candidate_addr: &str,
    max_per_subnet: usize,
) -> bool {
    let candidate_subnet = match extract_subnet(candidate_addr) {
        Some(s) => s,
        None => return true, // DNS or unknown — allow by default.
    };

    let same_subnet_count = existing_addrs
        .iter()
        .filter(|a| extract_subnet(a) == Some(candidate_subnet))
        .count();

    same_subnet_count < max_per_subnet
}

/// Maximum inbound connections per /16 subnet (IPv4) or /48 prefix (IPv6).
pub const MAX_INBOUND_PER_SUBNET: usize = 4;

/// Check whether accepting a new inbound connection from `candidate_addr`
/// would violate the per-subnet inbound diversity limit.
///
/// Returns `true` if the connection is allowed, `false` if it would exceed
/// `max_per_subnet` inbound connections from the same subnet.
/// Non-IP addresses (DNS) are allowed by default.
pub fn check_inbound_subnet_diversity(
    existing_inbound_addrs: &[String],
    candidate_addr: &str,
    max_per_subnet: usize,
) -> bool {
    let candidate_subnet = match extract_subnet(candidate_addr) {
        Some(s) => s,
        None => return true, // DNS or unknown — allow by default.
    };

    let same_subnet_count = existing_inbound_addrs
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
            misbehavior_window: std::collections::VecDeque::new(),
            last_misbehavior: None,
            last_ban_reason: None,
        }
    }

    // --- extract_subnet: IPv4 ---

    #[test]
    fn extract_subnet_ipv4() {
        assert_eq!(
            extract_subnet("/ip4/192.168.1.5/tcp/8780"),
            Some(SubnetId::V4(0xC0A8)) // 192 << 8 | 168
        );
        assert_eq!(
            extract_subnet("/ip4/10.0.42.1/tcp/8780"),
            Some(SubnetId::V4(0x0A00)) // 10 << 8 | 0
        );
    }

    #[test]
    fn extract_subnet_non_ip_returns_none() {
        assert_eq!(extract_subnet("/dns4/example.com/tcp/8780"), None);
    }

    // --- extract_subnet: IPv6 ---

    #[test]
    fn extract_subnet_ipv6() {
        // 2001:db8:1:: → /48 prefix (segs[0..3] = 0x2001, 0x0db8, 0x0001)
        assert_eq!(
            extract_subnet("/ip6/2001:db8:1::1/tcp/8780"),
            Some(SubnetId::V6(0x2001, 0x0db8, 0x0001))
        );
        // Different host within same /48 prefix
        assert_eq!(
            extract_subnet("/ip6/2001:db8:1::2/tcp/8780"),
            Some(SubnetId::V6(0x2001, 0x0db8, 0x0001))
        );
    }

    #[test]
    fn extract_subnet_ipv6_loopback() {
        // ::1 → first three groups are all 0
        assert_eq!(
            extract_subnet("/ip6/::1/tcp/8780"),
            Some(SubnetId::V6(0, 0, 0))
        );
    }

    #[test]
    fn extract_subnet_ipv6_different_prefixes() {
        let a = extract_subnet("/ip6/2001:db8:1::1/tcp/8780");
        let b = extract_subnet("/ip6/2001:db8:2::1/tcp/8780");
        // Third group differs (0x0001 vs 0x0002) → different /48 prefixes
        assert_ne!(a, b);
    }

    // --- quality score ---

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

    // --- IPv4 outbound diversity ---

    #[test]
    fn diversity_allows_first_connection() {
        let existing: Vec<String> = vec![];
        assert!(check_subnet_diversity(
            &existing,
            "/ip4/192.168.1.1/tcp/8780",
            2
        ));
    }

    #[test]
    fn diversity_blocks_over_limit() {
        let existing = vec![
            "/ip4/192.168.1.1/tcp/8780".to_string(),
            "/ip4/192.168.2.2/tcp/8780".to_string(),
        ];
        // Same /16 subnet (192.168.x.x) — should be blocked at max=2.
        assert!(!check_subnet_diversity(
            &existing,
            "/ip4/192.168.3.3/tcp/8780",
            2
        ));
    }

    #[test]
    fn diversity_allows_different_subnet() {
        let existing = vec![
            "/ip4/192.168.1.1/tcp/8780".to_string(),
            "/ip4/192.168.2.2/tcp/8780".to_string(),
        ];
        // Different /16 subnet (10.0.x.x) — should be allowed.
        assert!(check_subnet_diversity(
            &existing,
            "/ip4/10.0.1.1/tcp/8780",
            2
        ));
    }

    // --- IPv4 inbound diversity ---

    #[test]
    fn inbound_diversity_allows_below_limit() {
        let existing = vec![
            "/ip4/192.168.1.1/tcp/8780".to_string(),
            "/ip4/192.168.2.2/tcp/8780".to_string(),
        ];
        assert!(check_inbound_subnet_diversity(
            &existing,
            "/ip4/192.168.3.3/tcp/8780",
            4
        ));
    }

    #[test]
    fn inbound_diversity_blocks_over_limit() {
        let existing = vec![
            "/ip4/10.0.1.1/tcp/8780".to_string(),
            "/ip4/10.0.2.2/tcp/8780".to_string(),
            "/ip4/10.0.3.3/tcp/8780".to_string(),
        ];
        assert!(!check_inbound_subnet_diversity(
            &existing,
            "/ip4/10.0.4.4/tcp/8780",
            3
        ));
    }

    // --- IPv6 outbound diversity ---

    #[test]
    fn ipv6_diversity_blocks_over_limit() {
        let existing = vec![
            "/ip6/2001:db8:1::1/tcp/8780".to_string(),
            "/ip6/2001:db8:1::2/tcp/8780".to_string(),
        ];
        // Same /48 prefix (2001:db8:1::/48) — should be blocked at max=2.
        assert!(!check_subnet_diversity(
            &existing,
            "/ip6/2001:db8:1::3/tcp/8780",
            2
        ));
    }

    #[test]
    fn ipv6_diversity_allows_different_prefix() {
        let existing = vec![
            "/ip6/2001:db8:1::1/tcp/8780".to_string(),
            "/ip6/2001:db8:1::2/tcp/8780".to_string(),
        ];
        // Different /48 prefix (2001:db8:2::/48) — should be allowed.
        assert!(check_subnet_diversity(
            &existing,
            "/ip6/2001:db8:2::1/tcp/8780",
            2
        ));
    }

    // --- worst peer selection ---

    #[test]
    fn worst_outbound_peer_selects_highest_score() {
        let state1 = make_peer_state(10, 0);
        let state2 = make_peer_state(500, 50);
        let peers = vec![
            ("/ip4/1.2.3.4/tcp/8780", &state1),
            ("/ip4/5.6.7.8/tcp/8780", &state2),
        ];
        let (idx, _score) = worst_outbound_peer(&peers).unwrap();
        assert_eq!(idx, 1); // state2 is worse (higher latency + ban score)
    }
}
