// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! K3-09: typed network-endpoint parsing and validation.
//!
//! One implementation used by startup (and available to setup/diagnostics) so
//! effective listeners are computed the same way everywhere:
//! - service endpoints parse as [`SocketAddr`] (IPv6-safe — no `split(':')`
//!   or string `replace` surgery);
//! - explicitly supplied invalid values are per-field ERRORS, never silently
//!   replaced with defaults;
//! - port collisions are detected by effective bind scope (wildcard binds
//!   conflict with any same-port bind; specific IPs conflict only with the
//!   same IP or a wildcard) BEFORE any listener starts.

use std::net::SocketAddr;

/// Parse a service endpoint, attributing errors to the config field.
pub fn parse_socket_addr(field: &str, value: &str) -> Result<SocketAddr, String> {
    value.parse::<SocketAddr>().map_err(|e| {
        format!(
            "[{field}] invalid socket address {value:?}: {e}. \
             Use IP:PORT — IPv6 addresses need brackets, e.g. \"[::1]:8783\"."
        )
    })
}

/// Rebind a loopback endpoint to the unspecified address of the SAME family
/// when remote access is enabled. Fixes the silent IPv6 bug: the old
/// `replace(\"127.0.0.1\", \"0.0.0.0\")` string surgery left `[::1]:...`
/// loopback-bound while the operator believed remote access was on.
/// Non-loopback addresses are returned unchanged (explicit operator choice).
pub fn rebind_for_remote(addr: SocketAddr) -> SocketAddr {
    let mut out = addr;
    match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_loopback() => {
            out.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
        std::net::IpAddr::V6(ip) if ip.is_loopback() => {
            out.set_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
        }
        _ => {}
    }
    out
}

/// Two binds conflict when they claim the same port and their bind scopes
/// overlap: equal IPs, or either side is a wildcard (0.0.0.0 / ::).
/// (Dual-stack nuance: an IPv4 and an IPv6 wildcard on the same port DO
/// conflict on platforms with dual-stack sockets — treated as a conflict
/// here to fail early rather than platform-dependently.)
fn scopes_conflict(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() {
        return false;
    }
    a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified()
}

/// Validate a set of named endpoints: every pair must be collision-free.
/// `extra_ports` lets callers add port-only services (P2P, faucet) that
/// bind wildcard by nature.
pub fn validate_endpoints(
    endpoints: &[(&str, SocketAddr)],
    extra_ports: &[(&str, u16)],
) -> Result<(), String> {
    for (i, (name_a, a)) in endpoints.iter().enumerate() {
        for (name_b, b) in endpoints.iter().skip(i + 1) {
            if scopes_conflict(*a, *b) {
                return Err(format!(
                    "port collision: [{name_a}] {a} and [{name_b}] {b} \
                     claim overlapping bind scopes — change one port"
                ));
            }
        }
        for (name_p, port) in extra_ports {
            if a.port() == *port {
                return Err(format!(
                    "port collision: [{name_a}] {a} claims port {port}, \
                     already owned by [{name_p}]"
                ));
            }
        }
    }
    // extra_ports vs each other
    for (i, (name_a, pa)) in extra_ports.iter().enumerate() {
        for (name_b, pb) in extra_ports.iter().skip(i + 1) {
            if pa == pb {
                return Err(format!(
                    "port collision: [{name_a}] and [{name_b}] both claim port {pa}"
                ));
            }
        }
    }
    Ok(())
}

/// IPv6-safe port extraction from a `host:port` service address string.
/// Returns `None` for anything that is not a full, valid socket address —
/// callers must decide their own fallback EXPLICITLY.
pub fn port_of(addr: &str) -> Option<u16> {
    addr.parse::<SocketAddr>().ok().map(|s| s.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_ipv6_and_rejects_garbage() {
        assert!(parse_socket_addr("api.rpc_addr", "127.0.0.1:8783").is_ok());
        assert!(parse_socket_addr("api.rpc_addr", "[::1]:8783").is_ok());
        assert!(parse_socket_addr("api.rpc_addr", "0.0.0.0:8783").is_ok());
        assert!(parse_socket_addr("api.rpc_addr", "localhost:8783").is_err(), "hostnames are not socket addrs");
        assert!(parse_socket_addr("api.rpc_addr", "127.0.0.1").is_err(), "missing port");
        assert!(parse_socket_addr("api.rpc_addr", "::1:8783").is_err(), "unbracketed IPv6 is ambiguous");
        assert!(parse_socket_addr("api.rpc_addr", "").is_err());
    }

    #[test]
    fn rebind_swaps_loopback_within_family_only() {
        let v4: SocketAddr = "127.0.0.1:8783".parse().unwrap();
        assert_eq!(rebind_for_remote(v4).to_string(), "0.0.0.0:8783");
        // The historical string-replace bug: IPv6 loopback stayed loopback.
        let v6: SocketAddr = "[::1]:8783".parse().unwrap();
        assert_eq!(rebind_for_remote(v6).to_string(), "[::]:8783");
        // Explicit non-loopback binds are the operator's choice — unchanged.
        let lan: SocketAddr = "192.168.1.7:8783".parse().unwrap();
        assert_eq!(rebind_for_remote(lan), lan);
    }

    #[test]
    fn collisions_by_scope_not_port_number_alone() {
        let a: SocketAddr = "127.0.0.1:8783".parse().unwrap();
        let b: SocketAddr = "192.168.1.7:8783".parse().unwrap();
        let w: SocketAddr = "0.0.0.0:8783".parse().unwrap();
        // Same port, different specific IPs: no conflict.
        assert!(validate_endpoints(&[("rpc", a), ("ws", b)], &[]).is_ok());
        // Wildcard swallows every same-port bind.
        assert!(validate_endpoints(&[("rpc", a), ("ws", w)], &[]).is_err());
        // Distinct ports never conflict.
        let c: SocketAddr = "127.0.0.1:8784".parse().unwrap();
        assert!(validate_endpoints(&[("rpc", a), ("ws", c)], &[]).is_ok());
        // Port-only services (P2P) conflict with any endpoint on that port.
        assert!(validate_endpoints(&[("rpc", a)], &[("p2p", 8783)]).is_err());
        assert!(validate_endpoints(&[("rpc", a)], &[("p2p", 8780), ("faucet", 8786)]).is_ok());
        assert!(validate_endpoints(&[], &[("p2p", 8780), ("faucet", 8780)]).is_err());
    }

    #[test]
    fn port_of_is_ipv6_safe() {
        assert_eq!(port_of("127.0.0.1:8783"), Some(8783));
        assert_eq!(port_of("[::1]:8783"), Some(8783), "the rsplit(':') approach broke this");
        assert_eq!(port_of("[2001:db8::1]:9000"), Some(9000));
        assert_eq!(port_of("not-an-addr"), None);
    }
}
