// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus configuration with tunable parameters.

use noble_core::{CYCLE_DURATION_SECS, MAX_BLOCK_SIZE};

/// Configuration for the consensus engine.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Duration of a consensus cycle in seconds (default: 1800 = 30 min).
    pub cycle_duration_secs: u64,
    /// Maximum serialized block size in bytes (default: 4 MB).
    pub max_block_size: usize,
    /// Maximum reorg depth before requesting full re-sync (default: 6).
    pub max_reorg_depth: u64,
    /// Divisor for plurality floor: leader needs ≥ total/divisor votes (default: 3 → 33%).
    pub plurality_floor_divisor: u64,
    /// Minimum connected peers required for consensus participation (GAP-C6, default: 3).
    pub min_peers_for_consensus: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            cycle_duration_secs: CYCLE_DURATION_SECS,
            max_block_size: MAX_BLOCK_SIZE,
            max_reorg_depth: 6,
            plurality_floor_divisor: 3,
            min_peers_for_consensus: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = ConsensusConfig::default();
        assert_eq!(cfg.cycle_duration_secs, 1800);
        assert_eq!(cfg.max_block_size, 4 * 1024 * 1024);
        assert_eq!(cfg.max_reorg_depth, 6);
        assert_eq!(cfg.plurality_floor_divisor, 3);
        assert_eq!(cfg.min_peers_for_consensus, 3);
    }
}
