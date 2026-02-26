// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus configuration with tunable parameters.

use noble_core::{CYCLE_DURATION_SECS, MAX_BLOCK_SIZE, MAX_REORG_DEPTH};

use crate::strategy::VotingStrategy;

/// Configuration for the consensus engine.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Duration of a consensus cycle in seconds (default: 1800 = 30 min).
    pub cycle_duration_secs: u64,
    /// Maximum serialized block size in bytes (default: 4 MB).
    pub max_block_size: usize,
    /// Maximum reorg depth before requesting full re-sync (default: 144, matching noble-core).
    pub max_reorg_depth: u64,
    /// Divisor for plurality floor: leader needs ≥ total/divisor votes (default: 3 → 33%).
    pub plurality_floor_divisor: u64,
    /// Minimum connected peers required for consensus participation (GAP-C6, default: 1).
    pub min_peers_for_consensus: usize,
    /// Voting strategy for Round 1 (Reflection phase). Default: FirstValid.
    pub voting_strategy: VotingStrategy,
    /// Voting strategy for Round 2 (Confirmation phase). Default: FollowMajority.
    pub confirmation_strategy: VotingStrategy,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            cycle_duration_secs: CYCLE_DURATION_SECS,
            max_block_size: MAX_BLOCK_SIZE,
            max_reorg_depth: MAX_REORG_DEPTH,
            plurality_floor_divisor: 3,
            min_peers_for_consensus: 1,
            voting_strategy: VotingStrategy::FirstValid,
            confirmation_strategy: VotingStrategy::FollowMajority,
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
        assert_eq!(cfg.max_reorg_depth, MAX_REORG_DEPTH);
        assert_eq!(cfg.max_reorg_depth, 144); // AUD2-H4: matches noble-core constant
        assert_eq!(cfg.plurality_floor_divisor, 3);
        assert_eq!(cfg.min_peers_for_consensus, 1);
    }
}
