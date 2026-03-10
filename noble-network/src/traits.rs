// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Trait abstractions for decoupling noble-network from storage/mempool.
//!
//! The node binary implements these traits and passes them to [`NetworkService`].
//! This keeps noble-network free of direct dependencies on noble-storage or noble-mempool.

use noble_core::{Block, BlockHeader, Transaction};

/// Provides block data for serving sync requests and validating announcements.
pub trait BlockProvider: Send + Sync {
    /// Get a full block by its hash.
    fn get_block(&self, hash: &[u8; 32]) -> Option<Block>;

    /// Get a full block by its height in the main chain.
    fn get_block_by_height(&self, height: u64) -> Option<Block>;

    /// Get a block header by its hash.
    fn get_block_header(&self, hash: &[u8; 32]) -> Option<BlockHeader>;

    /// Returns `(height, tip_hash)` of the current chain tip.
    fn chain_tip(&self) -> (u64, [u8; 32]);

    /// Get the block hash at a specific height (lightweight — no full block deserialization).
    fn get_block_hash_by_height(&self, height: u64) -> Option<[u8; 32]>;

    /// Cumulative transaction count across all blocks (fork KPI).
    fn total_transactions(&self) -> u64 {
        0
    }

    /// Mean vote count in winning blocks (fork KPI).
    fn avg_votes_per_block(&self) -> f32 {
        0.0
    }
}

/// Provides transaction data for serving tx requests.
pub trait TxProvider: Send + Sync {
    /// Get a transaction by its ID.
    fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<Transaction>;

    /// Check whether a transaction is known (in mempool or confirmed).
    fn has_transaction(&self, tx_id: &[u8; 32]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify traits are object-safe (can be used as `dyn BlockProvider`).
    #[test]
    fn block_provider_is_object_safe() {
        fn _assert_object_safe(_: &dyn BlockProvider) {}
    }

    #[test]
    fn tx_provider_is_object_safe() {
        fn _assert_object_safe(_: &dyn TxProvider) {}
    }
}
