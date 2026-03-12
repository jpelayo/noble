// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Block-related RPC methods: getLatestBlock, getBlockCount, getBlock, getBlockHeader,
//! getBlockRange, getChainStats.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use noble_consensus::ConsensusStateMachine;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

/// Maximum number of block headers returned by `getBlockRange`.
const MAX_BLOCK_RANGE: u64 = 100;

#[rpc(server, namespace = "noble")]
pub trait BlockApi {
    /// Get the most recent block.
    #[method(name = "getLatestBlock")]
    async fn get_latest_block(&self) -> Result<BlockResponse, ErrorObjectOwned>;

    /// Get the current chain height and tip hash.
    #[method(name = "getBlockCount")]
    async fn get_block_count(&self) -> Result<BlockCountResponse, ErrorObjectOwned>;

    /// Get a block by height (number) or hash (hex string).
    /// Accepts a `serde_json::Value` to support both parameter types.
    #[method(name = "getBlock")]
    async fn get_block(
        &self,
        block_ref: serde_json::Value,
    ) -> Result<BlockResponse, ErrorObjectOwned>;

    /// Get a block header by height (number) or hash (hex string).
    #[method(name = "getBlockHeader")]
    async fn get_block_header(
        &self,
        block_ref: serde_json::Value,
    ) -> Result<BlockHeaderResponse, ErrorObjectOwned>;

    /// Get a range of block headers. Returns up to 100 headers.
    #[method(name = "getBlockRange")]
    async fn get_block_range(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeaderResponse>, ErrorObjectOwned>;

    /// Get chain statistics.
    #[method(name = "getChainStats")]
    async fn get_chain_stats(&self) -> Result<ChainStatsResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> BlockApiServer for Arc<ApiState<S>> {
    async fn get_latest_block(&self) -> Result<BlockResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let tip = storage
            .get_chain_tip()
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::BlockNotFound("chain is empty".into()))?;

        let block = storage.get_block(&tip.block_hash).map_err(ApiError::from)?;
        Ok(block_to_response(&block, &tip.block_hash, self.chain_id.load(std::sync::atomic::Ordering::Relaxed)))
    }

    async fn get_block_count(&self) -> Result<BlockCountResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let tip = storage
            .get_chain_tip()
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::BlockNotFound("chain is empty".into()))?;

        Ok(BlockCountResponse {
            height: tip.height,
            block_hash: hash_to_hex(&tip.block_hash),
        })
    }

    async fn get_block(
        &self,
        block_ref: serde_json::Value,
    ) -> Result<BlockResponse, ErrorObjectOwned> {
        let storage = self.storage.read();

        let (block, block_hash) = if let Some(height) = block_ref.as_u64() {
            // Lookup by height
            let bh = storage
                .get_block_hash_by_height(height)
                .map_err(ApiError::from)?;
            let block = storage.get_block(&bh).map_err(ApiError::from)?;
            (block, bh)
        } else if let Some(hash_str) = block_ref.as_str() {
            // Lookup by hash
            let bh = parse_hash(hash_str)?;
            let block = storage.get_block(&bh).map_err(ApiError::from)?;
            (block, bh)
        } else {
            return Err(ApiError::Internal(
                "block_ref must be a number (height) or string (hash)".into(),
            )
            .into());
        };

        Ok(block_to_response(&block, &block_hash, self.chain_id.load(std::sync::atomic::Ordering::Relaxed)))
    }

    async fn get_block_header(
        &self,
        block_ref: serde_json::Value,
    ) -> Result<BlockHeaderResponse, ErrorObjectOwned> {
        let storage = self.storage.read();

        let (header, block_hash) = if let Some(height) = block_ref.as_u64() {
            let bh = storage
                .get_block_hash_by_height(height)
                .map_err(ApiError::from)?;
            let header = storage.get_block_header(&bh).map_err(ApiError::from)?;
            (header, bh)
        } else if let Some(hash_str) = block_ref.as_str() {
            let bh = parse_hash(hash_str)?;
            let header = storage.get_block_header(&bh).map_err(ApiError::from)?;
            (header, bh)
        } else {
            return Err(ApiError::Internal(
                "block_ref must be a number (height) or string (hash)".into(),
            )
            .into());
        };

        let cycle = self.consensus.read().cycle_for_timestamp(header.timestamp);

        Ok(BlockHeaderResponse {
            height: header.height,
            hash: hash_to_hex(&block_hash),
            prev_hash: hash_to_hex(&header.prev_block_hash),
            merkle_root: hash_to_hex(&header.merkle_root),
            timestamp: header.timestamp,
            tx_count: header.tx_count,
            validator_id: header.validator_id.to_address(),
            cycle,
        })
    }

    async fn get_block_range(
        &self,
        start_height: u64,
        count: u64,
    ) -> Result<Vec<BlockHeaderResponse>, ErrorObjectOwned> {
        let count = count.min(MAX_BLOCK_RANGE);
        let storage = self.storage.read();
        let consensus = self.consensus.read();
        let mut headers = Vec::with_capacity(count as usize);

        for h in start_height..start_height.saturating_add(count) {
            match storage.get_block_hash_by_height(h) {
                Ok(bh) => match storage.get_block_header(&bh) {
                    Ok(header) => {
                        let cycle = consensus.cycle_for_timestamp(header.timestamp);
                        headers.push(BlockHeaderResponse {
                            height: header.height,
                            hash: hash_to_hex(&bh),
                            prev_hash: hash_to_hex(&header.prev_block_hash),
                            merkle_root: hash_to_hex(&header.merkle_root),
                            timestamp: header.timestamp,
                            tx_count: header.tx_count,
                            validator_id: header.validator_id.to_address(),
                            cycle,
                        });
                    }
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        }

        Ok(headers)
    }

    async fn get_chain_stats(&self) -> Result<ChainStatsResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let tip = storage.get_chain_tip().map_err(ApiError::from)?;

        let height = tip.as_ref().map(|t| t.height).unwrap_or(0);

        // H-004: Compute total_transactions by summing tx_count from block headers.
        // Walk the last `height + 1` blocks (capped at 10,000 for performance).
        let scan_start = height.saturating_sub(9_999);
        let mut total_tx: u64 = 0;
        for h in scan_start..=height {
            match storage.get_block_hash_by_height(h) {
                Ok(bh) => {
                    if let Ok(header) = storage.get_block_header(&bh) {
                        total_tx += header.tx_count as u64;
                    }
                }
                Err(_) => break,
            }
        }

        Ok(ChainStatsResponse {
            height,
            total_transactions: total_tx,
            chain_id: self.chain_id.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}
