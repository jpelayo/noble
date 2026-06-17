// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Swarm construction with TCP + Noise + Yamux transport.

use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::{noise, tcp, yamux, Swarm, SwarmBuilder};

use crate::behaviour::NobleBehaviour;
use crate::config::NetworkConfig;
use crate::error::NetworkError;

/// Explicit per-connection stream ceiling for the yamux multiplexer.
///
/// libp2p's `yamux::Config::default()` caps concurrent streams at 512. On a
/// long-lived connection carrying gossipsub + the two request-response
/// protocols + ping/identify/kad, that ceiling was hit in production
/// (`yamux: maximum number of streams reached`), which wedged new
/// sync/status substreams while the already-open gossip streams survived —
/// the exact "connected peer, dead request/response" failure. We set the cap
/// explicitly, with generous headroom over the worst-case honest load (≤64+64
/// concurrent req-resp streams, themselves capped in `behaviour.rs`, plus a
/// handful of long-lived gossip streams), so a libp2p default change can't
/// silently re-introduce the wedge. Pinned by `yamux_stream_cap_is_explicit`.
pub const MAX_YAMUX_STREAMS: usize = 1024;

/// Idle-connection reap timeout (seconds). A connection with no active streams
/// for this long is closed. Healthy peers keep long-lived gossipsub streams so
/// they are never "idle"; this only reaps genuinely dead / stream-less sockets.
/// Fast liveness for mute-but-connected peers is handled by ping-failure
/// disconnect in `service.rs`, not by this timeout — so this stays generous to
/// avoid churning quiet-but-healthy links (was 7200s = 2h).
pub const IDLE_CONNECTION_TIMEOUT_SECS: u64 = 1800;

/// Build and return a configured libp2p [`Swarm`] with a [`NobleBehaviour`].
///
/// Transport stack: TCP + Noise (encryption) + Yamux (multiplexing).
pub fn build_swarm(
    keypair: Keypair,
    config: &NetworkConfig,
) -> Result<Swarm<NobleBehaviour>, NetworkError> {
    let behaviour = NobleBehaviour::new(&keypair, config)
        .map_err(|e| NetworkError::Transport(e.to_string()))?;

    SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                // Explicit stream cap (see MAX_YAMUX_STREAMS) — not the default.
                let mut cfg = yamux::Config::default();
                cfg.set_max_num_streams(MAX_YAMUX_STREAMS);
                cfg
            },
        )
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_behaviour(|_| behaviour)
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(IDLE_CONNECTION_TIMEOUT_SECS))
        })
        .build()
        .pipe_ok()
}

/// Extension trait to make `Swarm` return compatible with our error type.
trait PipeOk: Sized {
    fn pipe_ok(self) -> Result<Self, NetworkError> {
        Ok(self)
    }
}

impl<T> PipeOk for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yamux_stream_cap_is_explicit() {
        // Pins the intended ceiling so a refactor or libp2p default change can't
        // silently revert to the 512 default that wedged production.
        assert_eq!(MAX_YAMUX_STREAMS, 1024);
        assert!(
            MAX_YAMUX_STREAMS > 128,
            "must exceed the worst-case 64+64 concurrent req-resp streams"
        );
    }

    #[tokio::test]
    async fn swarm_builds_and_listens() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::local_test();
        let mut swarm = build_swarm(keypair, &config).unwrap();

        let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let listener_id = swarm.listen_on(addr).unwrap();
        assert!(!listener_id.to_string().is_empty());
    }
}
