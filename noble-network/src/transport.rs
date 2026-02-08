// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Swarm construction with TCP + Noise + Yamux transport.

use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::{noise, tcp, yamux, Swarm, SwarmBuilder};

use crate::behaviour::NobleBehaviour;
use crate::config::NetworkConfig;
use crate::error::NetworkError;

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
            yamux::Config::default,
        )
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_behaviour(|_| behaviour)
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
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

    #[tokio::test]
    async fn swarm_builds_and_listens() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::testnet();
        let mut swarm = build_swarm(keypair, &config).unwrap();

        let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let listener_id = swarm.listen_on(addr).unwrap();
        assert!(listener_id.to_string().len() > 0);
    }
}
