// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus configuration.
//!
//! Protocol constants are hardcoded — they define the blockchain's rules and
//! cannot be changed by operators.  Operator preferences (voting strategy,
//! fork resolution) are passed in by the node layer from TOML config.

use noble_core::{MAX_BLOCK_SIZE, MAX_REORG_DEPTH};

use crate::fork_resolver::ForkResolutionStrategy;
use crate::strategy::VotingStrategy;

/// Configuration for the consensus engine.
///
/// Protocol constants are set by `ConsensusConfig::default()` and must not
/// be overridden.  Operator preferences have no default in this struct —
/// the caller (node layer) must provide them from the TOML config.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    // ── Protocol constants (hardcoded, not configurable) ──

    /// Maximum serialized block size in bytes (4 MB).
    pub max_block_size: usize,
    /// Maximum reorg depth before requesting full re-sync (144).
    pub max_reorg_depth: u64,
    /// Divisor for plurality floor: leader needs ≥ total/divisor votes (3 → 33%).
    pub plurality_floor_divisor: u64,
    /// Minimum connected peers required for consensus participation (2).
    pub min_peers_for_consensus: usize,
    /// Minimum distinct validator keys required to commit a block (Dual-Witness Rule, 2).
    pub min_unique_voters: usize,
    /// Consecutive clean cycles required to finalize a block (3).
    pub confirmation_threshold: u32,
    /// Create a checkpoint every N blocks (30).
    pub checkpoint_interval: u64,

    // ── Operator preferences (from TOML, no engine default) ──

    /// Voting strategy for Round 1.  Set by operator via TOML.
    pub voting_strategy: VotingStrategy,
    /// Voting strategy for Round 2 (confirmation).  Set by operator via TOML.
    pub confirmation_strategy: VotingStrategy,
    /// Fork resolution strategy.  Set by operator via TOML.
    pub fork_resolution_strategy: ForkResolutionStrategy,
    /// Minimum cycles a fork must persist before auto-resolution.  Set by operator via TOML.
    pub fork_resolution_delay_cycles: u32,
}

impl Default for ConsensusConfig {
    /// Returns protocol constants only.  Operator preferences are set to
    /// placeholder values — the node layer MUST overwrite them from TOML.
    fn default() -> Self {
        Self {
            // Protocol constants
            max_block_size: MAX_BLOCK_SIZE,
            max_reorg_depth: MAX_REORG_DEPTH,
            plurality_floor_divisor: 3,
            min_peers_for_consensus: 2,
            min_unique_voters: 2,
            confirmation_threshold: 3,
            checkpoint_interval: 30,
            // Operator preferences — placeholders, overwritten by node layer.
            voting_strategy: VotingStrategy::default(),
            confirmation_strategy: VotingStrategy::FollowMajority,
            fork_resolution_strategy: ForkResolutionStrategy::LongestMostLegitimate,
            fork_resolution_delay_cycles: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants() {
        let cfg = ConsensusConfig::default();
        assert_eq!(cfg.max_block_size, 4 * 1024 * 1024);
        assert_eq!(cfg.max_reorg_depth, 144);
        assert_eq!(cfg.plurality_floor_divisor, 3);
        assert_eq!(cfg.min_peers_for_consensus, 2);
        assert_eq!(cfg.min_unique_voters, 2);
        assert_eq!(cfg.confirmation_threshold, 3);
        assert_eq!(cfg.checkpoint_interval, 30);
    }
}
