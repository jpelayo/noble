// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus configuration with tunable parameters.

use noble_core::{MAX_BLOCK_SIZE, MAX_REORG_DEPTH};

use crate::fork_resolver::ForkResolutionStrategy;
use crate::strategy::VotingStrategy;

/// Configuration for the consensus engine.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Maximum serialized block size in bytes (default: 4 MB).
    pub max_block_size: usize,
    /// Maximum reorg depth before requesting full re-sync (default: 144, matching noble-core).
    pub max_reorg_depth: u64,
    /// Divisor for plurality floor: leader needs ≥ total/divisor votes (default: 3 → 33%).
    pub plurality_floor_divisor: u64,
    /// Minimum connected peers required for consensus participation (GAP-C6, default: 2).
    /// Set to 2 to prevent single-node "ultraforking" while allowing small chains.
    pub min_peers_for_consensus: usize,
    /// Minimum number of distinct validator keys that must vote for a block
    /// before it can be committed (Dual-Witness Rule). Default: 2.
    pub min_unique_voters: usize,
    /// Voting strategy for Round 1 (Reflection phase). Default: FirstValid.
    pub voting_strategy: VotingStrategy,
    /// Voting strategy for Round 2 (Confirmation phase). Default: FollowMajority.
    pub confirmation_strategy: VotingStrategy,
    /// Number of consecutive clean cycles required to finalize a block (default: 3).
    pub confirmation_threshold: u32,
    /// Fork resolution strategy (default: LongestMostLegitimate — auto-resolve
    /// when a peer's fork is >3 blocks ahead, using decay-weighted vote
    /// legitimacy as tiebreaker for similar-height chains).
    pub fork_resolution_strategy: ForkResolutionStrategy,
    /// Minimum cycles a fork must persist before auto-resolution (default: 3).
    pub fork_resolution_delay_cycles: u32,
    /// Create a checkpoint every N blocks (0 = disabled, default: 30).
    pub checkpoint_interval: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            max_block_size: MAX_BLOCK_SIZE,
            max_reorg_depth: MAX_REORG_DEPTH,
            plurality_floor_divisor: 3,
            min_peers_for_consensus: 2,
            min_unique_voters: 2,
            voting_strategy: VotingStrategy::FirstValid,
            confirmation_strategy: VotingStrategy::FollowMajority,
            confirmation_threshold: 3,
            fork_resolution_strategy: ForkResolutionStrategy::LongestMostLegitimate,
            fork_resolution_delay_cycles: 3,
            checkpoint_interval: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = ConsensusConfig::default();
        assert_eq!(cfg.max_block_size, 4 * 1024 * 1024);
        assert_eq!(cfg.max_reorg_depth, MAX_REORG_DEPTH);
        assert_eq!(cfg.max_reorg_depth, 144); // AUD2-H4: matches noble-core constant
        assert_eq!(cfg.plurality_floor_divisor, 3);
        assert_eq!(cfg.min_peers_for_consensus, 2);
        assert_eq!(cfg.min_unique_voters, 2);
        assert_eq!(cfg.confirmation_threshold, 3);
        assert_eq!(
            cfg.fork_resolution_strategy,
            ForkResolutionStrategy::LongestMostLegitimate
        );
        assert_eq!(cfg.fork_resolution_delay_cycles, 3);
        assert_eq!(cfg.checkpoint_interval, 30);
    }
}
