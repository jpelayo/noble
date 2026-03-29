// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Storage pruning engine — 3 modes for managing disk usage.
//!
//! - **Archive**: keep everything (default).
//! - **Moderate**: keep full blocks for the most recent `keep_blocks` blocks;
//!   prune transaction bodies from older blocks but retain headers and indexes.
//! - **Aggressive**: keep only the most recent `keep_blocks` blocks;
//!   delete all data (blocks, tx index, checksums) for older heights.

use serde::{Deserialize, Serialize};

use crate::error::StorageError;
use crate::traits::StorageEngine;

/// Pruning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PruningMode {
    /// Keep all blocks and transactions. No pruning.
    Archive,
    /// Keep full block data for recent blocks; prune tx bodies from older blocks.
    /// Headers, indexes, and balances are retained for all heights.
    Moderate,
    /// Keep only recent blocks; delete older blocks, their transactions, and
    /// associated indexes entirely. Headers are retained for sync.
    Aggressive,
}

impl Default for PruningMode {
    fn default() -> Self {
        Self::Archive
    }
}

impl PruningMode {
    /// Parse from a config string.
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "moderate" => Self::Moderate,
            "aggressive" => Self::Aggressive,
            _ => Self::Archive,
        }
    }

    /// Display name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Moderate => "moderate",
            Self::Aggressive => "aggressive",
        }
    }
}

/// Configuration for the pruning engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Pruning mode.
    pub mode: PruningMode,
    /// Number of recent blocks to keep full data for (moderate/aggressive).
    /// Default: 10,000 blocks (~111 days at 16-min cycles).
    pub keep_blocks: u64,
    /// Maximum number of blocks to prune per invocation (to limit I/O).
    /// Default: 500.
    pub batch_size: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            mode: PruningMode::Archive,
            keep_blocks: 10_000,
            batch_size: 500,
        }
    }
}

/// Result of a pruning run.
#[derive(Debug, Clone, Serialize)]
pub struct PruningResult {
    /// Number of blocks pruned in this run.
    pub blocks_pruned: u64,
    /// Number of transactions removed.
    pub transactions_removed: u64,
    /// The lowest height that still has full block data after pruning.
    pub lowest_full_height: u64,
    /// Whether more pruning is needed (batch was exhausted).
    pub more_remaining: bool,
}

/// Pruning engine that operates on a `StorageEngine`.
pub struct PruningEngine {
    config: PruningConfig,
}

impl PruningEngine {
    /// Create a new pruning engine.
    pub fn new(config: PruningConfig) -> Self {
        Self { config }
    }

    /// Get the current pruning mode.
    pub fn mode(&self) -> PruningMode {
        self.config.mode
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PruningConfig {
        &self.config
    }

    /// Update the pruning mode at runtime.
    pub fn set_mode(&mut self, mode: PruningMode) {
        self.config.mode = mode;
    }

    /// Run one pruning pass. Returns a summary of what was pruned.
    ///
    /// This should be called periodically (e.g. after each cycle boundary).
    /// It is safe to call at any time; if there is nothing to prune, it returns
    /// a zero-count result.
    pub fn run<S: StorageEngine>(&self, storage: &S) -> Result<PruningResult, StorageError> {
        match self.config.mode {
            PruningMode::Archive => Ok(PruningResult {
                blocks_pruned: 0,
                transactions_removed: 0,
                lowest_full_height: 0,
                more_remaining: false,
            }),
            PruningMode::Moderate => self.run_moderate(storage),
            PruningMode::Aggressive => self.run_aggressive(storage),
        }
    }

    /// Moderate pruning: remove transaction bodies from blocks older than
    /// `keep_blocks` from the current tip.
    fn run_moderate<S: StorageEngine>(&self, storage: &S) -> Result<PruningResult, StorageError> {
        let tip = match storage.get_chain_tip()? {
            Some(t) => t,
            None => {
                return Ok(PruningResult {
                    blocks_pruned: 0,
                    transactions_removed: 0,
                    lowest_full_height: 0,
                    more_remaining: false,
                })
            }
        };

        let cutoff = tip.height.saturating_sub(self.config.keep_blocks);
        if cutoff == 0 {
            return Ok(PruningResult {
                blocks_pruned: 0,
                transactions_removed: 0,
                lowest_full_height: 0,
                more_remaining: false,
            });
        }

        let mut blocks_pruned = 0u64;
        let mut txs_removed = 0u64;

        // Find the lowest unpruned height by scanning from height 1.
        let start = self.find_lowest_full_block(storage, cutoff)?;

        for height in start..=cutoff {
            if blocks_pruned >= self.config.batch_size {
                return Ok(PruningResult {
                    blocks_pruned,
                    transactions_removed: txs_removed,
                    lowest_full_height: height,
                    more_remaining: true,
                });
            }

            let hash = match storage.get_block_hash_by_height(height) {
                Ok(h) => h,
                Err(StorageError::NotFound) => continue,
                Err(e) => return Err(e),
            };

            // Get block to count transactions, then prune bodies.
            match storage.get_block(&hash) {
                Ok(block) => {
                    let tx_count = block.transactions.len() as u64;
                    storage.prune_block_body(&hash)?;
                    txs_removed += tx_count;
                    blocks_pruned += 1;
                }
                Err(StorageError::NotFound) => continue, // already pruned
                Err(e) => return Err(e),
            }
        }

        Ok(PruningResult {
            blocks_pruned,
            transactions_removed: txs_removed,
            lowest_full_height: cutoff + 1,
            more_remaining: false,
        })
    }

    /// Aggressive pruning: delete blocks, transactions, and indexes older than
    /// `keep_blocks` from the current tip.
    fn run_aggressive<S: StorageEngine>(&self, storage: &S) -> Result<PruningResult, StorageError> {
        let tip = match storage.get_chain_tip()? {
            Some(t) => t,
            None => {
                return Ok(PruningResult {
                    blocks_pruned: 0,
                    transactions_removed: 0,
                    lowest_full_height: 0,
                    more_remaining: false,
                })
            }
        };

        let cutoff = tip.height.saturating_sub(self.config.keep_blocks);
        if cutoff == 0 {
            return Ok(PruningResult {
                blocks_pruned: 0,
                transactions_removed: 0,
                lowest_full_height: 0,
                more_remaining: false,
            });
        }

        let mut blocks_pruned = 0u64;
        let mut txs_removed = 0u64;
        let start = self.find_lowest_full_block(storage, cutoff)?;

        for height in start..=cutoff {
            if blocks_pruned >= self.config.batch_size {
                return Ok(PruningResult {
                    blocks_pruned,
                    transactions_removed: txs_removed,
                    lowest_full_height: height,
                    more_remaining: true,
                });
            }

            let hash = match storage.get_block_hash_by_height(height) {
                Ok(h) => h,
                Err(StorageError::NotFound) => continue,
                Err(e) => return Err(e),
            };

            match storage.get_block(&hash) {
                Ok(block) => {
                    let tx_count = block.transactions.len() as u64;
                    storage.delete_block_data(&hash, height)?;
                    txs_removed += tx_count;
                    blocks_pruned += 1;
                }
                Err(StorageError::NotFound) => {
                    // Block body already gone, try to clean the hash index.
                    storage.delete_block_data(&hash, height)?;
                    blocks_pruned += 1;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(PruningResult {
            blocks_pruned,
            transactions_removed: txs_removed,
            lowest_full_height: cutoff + 1,
            more_remaining: false,
        })
    }

    /// Find the lowest height that still has full block data,
    /// starting from height 1 up to `max_height`.
    fn find_lowest_full_block<S: StorageEngine>(
        &self,
        storage: &S,
        _max_height: u64,
    ) -> Result<u64, StorageError> {
        // Check if the stored "pruned_up_to" marker exists.
        if let Ok(marker) = storage.get_pruning_marker() {
            if marker > 0 {
                return Ok(marker + 1);
            }
        }
        Ok(1) // start from block 1 (genesis at 0 is never pruned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_archive() {
        let config = PruningConfig::default();
        assert_eq!(config.mode, PruningMode::Archive);
        assert_eq!(config.keep_blocks, 10_000);
        assert_eq!(config.batch_size, 500);
    }

    #[test]
    fn pruning_mode_from_str() {
        assert_eq!(
            PruningMode::from_str_config("archive"),
            PruningMode::Archive
        );
        assert_eq!(
            PruningMode::from_str_config("moderate"),
            PruningMode::Moderate
        );
        assert_eq!(
            PruningMode::from_str_config("aggressive"),
            PruningMode::Aggressive
        );
        assert_eq!(
            PruningMode::from_str_config("unknown"),
            PruningMode::Archive
        );
        assert_eq!(
            PruningMode::from_str_config("MODERATE"),
            PruningMode::Moderate
        );
    }

    #[test]
    fn pruning_mode_names() {
        assert_eq!(PruningMode::Archive.name(), "archive");
        assert_eq!(PruningMode::Moderate.name(), "moderate");
        assert_eq!(PruningMode::Aggressive.name(), "aggressive");
    }

    #[test]
    fn archive_mode_prunes_nothing() {
        let engine = PruningEngine::new(PruningConfig::default());
        let storage = crate::MemoryStorage::new();
        let result = engine.run(&storage).unwrap();
        assert_eq!(result.blocks_pruned, 0);
        assert_eq!(result.transactions_removed, 0);
        assert!(!result.more_remaining);
    }

    #[test]
    fn moderate_mode_noop_when_chain_short() {
        let config = PruningConfig {
            mode: PruningMode::Moderate,
            keep_blocks: 10_000,
            batch_size: 100,
        };
        let engine = PruningEngine::new(config);
        let storage = crate::MemoryStorage::new();
        // Empty chain — nothing to prune.
        let result = engine.run(&storage).unwrap();
        assert_eq!(result.blocks_pruned, 0);
    }

    #[test]
    fn aggressive_mode_noop_when_chain_short() {
        let config = PruningConfig {
            mode: PruningMode::Aggressive,
            keep_blocks: 10_000,
            batch_size: 100,
        };
        let engine = PruningEngine::new(config);
        let storage = crate::MemoryStorage::new();
        let result = engine.run(&storage).unwrap();
        assert_eq!(result.blocks_pruned, 0);
    }

    #[test]
    fn set_mode_updates_engine() {
        let mut engine = PruningEngine::new(PruningConfig::default());
        assert_eq!(engine.mode(), PruningMode::Archive);
        engine.set_mode(PruningMode::Moderate);
        assert_eq!(engine.mode(), PruningMode::Moderate);
    }

    #[test]
    fn pruning_result_serializes() {
        let result = PruningResult {
            blocks_pruned: 42,
            transactions_removed: 100,
            lowest_full_height: 1000,
            more_remaining: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("42"));
        assert!(json.contains("1000"));
    }
}
