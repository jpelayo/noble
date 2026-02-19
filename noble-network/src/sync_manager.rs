// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Headers-first chain synchronization state machine.
//!
//! The sync flow:
//! 1. Detect: compare local tip with best peer tip.
//! 2. Request headers from the best peer (batches of [`MAX_HEADERS_PER_REQUEST`]).
//! 3. Validate header chain: prev_block_hash linkage, monotonic heights (GAP-M2).
//! 4. Request full blocks for validated headers.
//! 5. Emit blocks to the node for storage and validation.

use std::collections::VecDeque;

use noble_core::BlockHeader;

use crate::error::NetworkError;
use crate::messages::SyncRequest;

/// Maximum headers to request in a single batch.
pub const MAX_HEADERS_PER_REQUEST: u32 = 2_000;

/// Maximum blocks to request in a single batch.
pub const MAX_BLOCKS_PER_BATCH: usize = 16;

/// Opaque peer identifier for the sync manager (serialized libp2p PeerId bytes).
pub type SyncPeerId = Vec<u8>;

/// The action the caller should take after a sync event.
#[derive(Debug, PartialEq)]
pub enum SyncAction {
    /// Send these sync requests to the peer.
    Request(Vec<SyncRequest>),
    /// Sync is complete up to this height.
    Complete(u64),
    /// Nothing to do (already idle or event was a no-op).
    None,
}

/// State of the sync FSM.
#[derive(Debug, Clone)]
pub enum SyncState {
    /// Not syncing.
    Idle,
    /// Downloading headers from a peer toward the target height.
    DownloadingHeaders {
        from_peer: SyncPeerId,
        target_height: u64,
    },
    /// Downloading full blocks for validated headers.
    DownloadingBlocks {
        from_peer: SyncPeerId,
        pending_hashes: VecDeque<[u8; 32]>,
        next_height: u64,
    },
}

/// Headers-first chain sync manager.
pub struct SyncManager {
    state: SyncState,
    local_height: u64,
    local_tip_hash: [u8; 32],
}

impl SyncManager {
    /// Create a new `SyncManager` with the local chain state.
    pub fn new(local_height: u64, local_tip_hash: [u8; 32]) -> Self {
        Self {
            state: SyncState::Idle,
            local_height,
            local_tip_hash,
        }
    }

    /// Check if we need to sync with a peer. Returns a [`SyncRequest`] to send
    /// if the peer is ahead and we are idle.
    pub fn check_sync_needed(
        &mut self,
        peer_id: SyncPeerId,
        peer_height: u64,
    ) -> Option<SyncRequest> {
        if self.is_syncing() {
            return None;
        }

        if peer_height <= self.local_height {
            return None;
        }

        self.state = SyncState::DownloadingHeaders {
            from_peer: peer_id,
            target_height: peer_height,
        };

        tracing::debug!(
            task = "sync_headers",
            "requesting headers from height {}",
            self.local_height
        );
        Some(SyncRequest::GetHeaders {
            start_hash: self.local_tip_hash,
            max_count: MAX_HEADERS_PER_REQUEST,
        })
    }

    /// Handle received headers. Validates header chain continuity (GAP-M2)
    /// and transitions to block downloading.
    ///
    /// Returns sync requests for the block download phase, or an error if
    /// the header chain is invalid.
    pub fn on_headers_received(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<SyncAction, NetworkError> {
        let from_peer = match &self.state {
            SyncState::DownloadingHeaders { from_peer, .. } => from_peer.clone(),
            _ => return Ok(SyncAction::None),
        };

        if headers.is_empty() {
            self.state = SyncState::Idle;
            tracing::info!(
                task = "sync_complete",
                "sync complete at height {}",
                self.local_height
            );
            return Ok(SyncAction::Complete(self.local_height));
        }

        // GAP-M2: Validate header chain continuity.
        self.validate_header_chain(&headers)?;

        // Collect block hashes to download.
        let hashes: VecDeque<[u8; 32]> = headers
            .iter()
            .map(|h| {
                h.compute_block_hash()
                    .map(|hash| *hash.as_bytes())
                    .unwrap_or([0; 32])
            })
            .collect();
        let next_height = self.local_height + 1;

        self.state = SyncState::DownloadingBlocks {
            from_peer,
            pending_hashes: hashes.clone(),
            next_height,
        };

        let requests = self.make_block_requests(&hashes);
        Ok(SyncAction::Request(requests))
    }

    /// Handle a received block during the download phase.
    /// Returns the next action: request more blocks, complete, or none.
    pub fn on_block_received(&mut self, block_hash: &[u8; 32]) -> SyncAction {
        match &mut self.state {
            SyncState::DownloadingBlocks {
                pending_hashes,
                next_height,
                ..
            } => {
                pending_hashes.retain(|h| h != block_hash);
                *next_height = next_height.saturating_add(1);

                if pending_hashes.is_empty() {
                    let new_height = *next_height - 1;
                    self.local_height = new_height;
                    self.state = SyncState::Idle;
                    tracing::info!(
                        task = "sync_complete",
                        "sync complete at height {}",
                        new_height
                    );
                    SyncAction::Complete(new_height)
                } else {
                    SyncAction::None
                }
            }
            _ => SyncAction::None,
        }
    }

    /// Whether a sync is currently in progress.
    pub fn is_syncing(&self) -> bool {
        !matches!(self.state, SyncState::Idle)
    }

    /// Returns sync progress as a fraction [0.0, 1.0].
    pub fn sync_progress(&self) -> f64 {
        match &self.state {
            SyncState::Idle => 1.0,
            SyncState::DownloadingHeaders { target_height, .. } => {
                if *target_height == 0 {
                    return 0.0;
                }
                (self.local_height as f64) / (*target_height as f64) * 0.5
            }
            SyncState::DownloadingBlocks {
                pending_hashes,
                next_height,
                ..
            } => {
                let total = *next_height - self.local_height + pending_hashes.len() as u64;
                if total == 0 {
                    return 1.0;
                }
                let done = total - pending_hashes.len() as u64;
                0.5 + (done as f64 / total as f64) * 0.5
            }
        }
    }

    /// Reset the sync manager to idle (e.g. after a peer disconnect).
    pub fn reset(&mut self) {
        self.state = SyncState::Idle;
    }

    /// Update local chain state (called after blocks are committed).
    pub fn update_local_tip(&mut self, height: u64, tip_hash: [u8; 32]) {
        self.local_height = height;
        self.local_tip_hash = tip_hash;
    }

    /// Current local height known to the sync manager.
    pub fn local_height(&self) -> u64 {
        self.local_height
    }

    /// Current sync state (for diagnostics).
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// GAP-M2: Validate that headers form a valid chain.
    fn validate_header_chain(&self, headers: &[BlockHeader]) -> Result<(), NetworkError> {
        if headers.is_empty() {
            return Ok(());
        }

        // Check that the first header connects to our chain.
        let first_prev = *headers[0].prev_block_hash.as_bytes();
        if first_prev != self.local_tip_hash {
            return Err(NetworkError::InvalidHeaderChain(format!(
                "first header prev_block_hash {:02x}{:02x}.. does not match local tip {:02x}{:02x}..",
                first_prev[0], first_prev[1],
                self.local_tip_hash[0], self.local_tip_hash[1],
            )));
        }

        // Validate chain linkage and monotonic heights.
        for i in 1..headers.len() {
            let prev = &headers[i - 1];
            let curr = &headers[i];

            let prev_hash = prev
                .compute_block_hash()
                .map_err(|e| NetworkError::InvalidHeaderChain(e.to_string()))?;

            if curr.prev_block_hash != prev_hash {
                return Err(NetworkError::InvalidHeaderChain(format!(
                    "header at index {} prev_block_hash does not match header at index {}",
                    i,
                    i - 1,
                )));
            }

            if curr.height != prev.height + 1 {
                return Err(NetworkError::InvalidHeaderChain(format!(
                    "non-monotonic height: {} -> {} at index {}",
                    prev.height, curr.height, i,
                )));
            }
        }

        Ok(())
    }

    /// Create block download requests from a set of hashes, batched by
    /// [`MAX_BLOCKS_PER_BATCH`].
    fn make_block_requests(&self, hashes: &VecDeque<[u8; 32]>) -> Vec<SyncRequest> {
        hashes
            .as_slices()
            .0
            .chunks(MAX_BLOCKS_PER_BATCH)
            .chain(hashes.as_slices().1.chunks(MAX_BLOCKS_PER_BATCH))
            .map(|chunk| SyncRequest::GetBlocks {
                hashes: chunk.to_vec(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::BlockHeader;
    use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};

    fn make_header_chain(
        start_prev_hash: [u8; 32],
        count: usize,
        start_height: u64,
    ) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = Hash256(start_prev_hash);

        for i in 0..count {
            let header = BlockHeader {
                version: 1,
                height: start_height + i as u64,
                timestamp: 1_700_000_000 + (i as u64 * 1800),
                prev_block_hash: prev_hash,
                merkle_root: Hash256::ZERO,
                tx_count: 0,
                validator_id: NoblePublicKey::Ed25519(vec![0; 32]),
                validator_sig: SignatureEnvelope {
                    scheme_id: 1,
                    public_key: vec![0; 32],
                    signature: vec![0; 64],
                },
            };
            prev_hash = header.compute_block_hash().unwrap();
            headers.push(header);
        }
        headers
    }

    #[test]
    fn new_sync_manager_is_idle() {
        let sm = SyncManager::new(0, [0; 32]);
        assert!(!sm.is_syncing());
        assert_eq!(sm.sync_progress(), 1.0);
        assert_eq!(sm.local_height(), 0);
    }

    #[test]
    fn check_sync_not_needed_when_peer_behind() {
        let mut sm = SyncManager::new(100, [1; 32]);
        let result = sm.check_sync_needed(vec![1], 50);
        assert!(result.is_none());
        assert!(!sm.is_syncing());
    }

    #[test]
    fn check_sync_needed_when_peer_ahead() {
        let mut sm = SyncManager::new(10, [0; 32]);
        let result = sm.check_sync_needed(vec![1], 100);
        assert!(result.is_some());
        assert!(sm.is_syncing());

        match result.unwrap() {
            SyncRequest::GetHeaders {
                start_hash,
                max_count,
            } => {
                assert_eq!(start_hash, [0; 32]);
                assert_eq!(max_count, MAX_HEADERS_PER_REQUEST);
            }
            _ => panic!("expected GetHeaders"),
        }
    }

    #[test]
    fn check_sync_ignored_while_syncing() {
        let mut sm = SyncManager::new(10, [0; 32]);
        sm.check_sync_needed(vec![1], 100);
        let result = sm.check_sync_needed(vec![2], 200);
        assert!(result.is_none());
    }

    #[test]
    fn on_headers_received_empty_completes() {
        let mut sm = SyncManager::new(10, [0; 32]);
        sm.check_sync_needed(vec![1], 100);
        let action = sm.on_headers_received(vec![]).unwrap();
        assert_eq!(action, SyncAction::Complete(10));
        assert!(!sm.is_syncing());
    }

    #[test]
    fn on_headers_received_valid_chain() {
        let tip_hash = [0xAA; 32];
        let mut sm = SyncManager::new(0, tip_hash);
        sm.check_sync_needed(vec![1], 5);

        let headers = make_header_chain(tip_hash, 3, 1);
        let action = sm.on_headers_received(headers).unwrap();
        match action {
            SyncAction::Request(reqs) => {
                assert!(!reqs.is_empty());
                for req in &reqs {
                    assert!(matches!(req, SyncRequest::GetBlocks { .. }));
                }
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn on_headers_received_broken_prev_hash_rejected() {
        let tip_hash = [0xAA; 32];
        let mut sm = SyncManager::new(0, tip_hash);
        sm.check_sync_needed(vec![1], 5);

        // First header's prev_block_hash doesn't match our tip.
        let bad_headers = make_header_chain([0xBB; 32], 3, 1);
        let result = sm.on_headers_received(bad_headers);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("prev_block_hash"));
    }

    #[test]
    fn on_block_received_completes_when_all_done() {
        let tip_hash = [0xAA; 32];
        let mut sm = SyncManager::new(0, tip_hash);
        sm.check_sync_needed(vec![1], 2);

        let headers = make_header_chain(tip_hash, 2, 1);
        let hashes: Vec<[u8; 32]> = headers
            .iter()
            .map(|h| *h.compute_block_hash().unwrap().as_bytes())
            .collect();
        sm.on_headers_received(headers).unwrap();

        let action = sm.on_block_received(&hashes[0]);
        assert_eq!(action, SyncAction::None);

        let action = sm.on_block_received(&hashes[1]);
        match action {
            SyncAction::Complete(h) => assert!(h > 0),
            _ => panic!("expected Complete"),
        }
        assert!(!sm.is_syncing());
    }

    #[test]
    fn reset_returns_to_idle() {
        let mut sm = SyncManager::new(0, [0; 32]);
        sm.check_sync_needed(vec![1], 100);
        assert!(sm.is_syncing());
        sm.reset();
        assert!(!sm.is_syncing());
    }

    #[test]
    fn update_local_tip() {
        let mut sm = SyncManager::new(0, [0; 32]);
        sm.update_local_tip(50, [0xFF; 32]);
        assert_eq!(sm.local_height(), 50);
    }
}
