// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Centralized alignment state — single source of truth for network status.
//!
//! Computed exclusively by `HealingManager::compute_alignment()` in `noble-node`.
//! Consumed by `getSyncStatus` RPC and the GUI sidebar via WebSocket events.
//! No independent alignment logic exists anywhere else.

/// Network alignment state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentState {
    /// height 0, 0 peers — or height > 0, 0 peers.
    Isolated,
    /// height 0, peers exist, no proposals yet.
    Bootstrapping,
    /// height 0, peers exist, proposals exist (genesis forming).
    Creating,
    /// height > 0, behind peers by > 10 blocks.
    Syncing,
    /// On the majority chain (> 50% of known peers agree).
    Aligned,
    /// Behind peers that share our chain_id — sequential catch-up in progress.
    CatchingUp,
    /// NOT on the majority chain, or healing fork dwell timer running.
    Diverged,
}

impl AlignmentState {
    /// Display label for the GUI sidebar and RPC responses.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Isolated => "Isolated",
            Self::Bootstrapping => "Bootstrapping",
            Self::Creating => "Creating",
            Self::Syncing => "Syncing",
            Self::Aligned => "Aligned",
            Self::CatchingUp => "Catching Up",
            Self::Diverged => "Diverged",
        }
    }

    /// CSS severity class for the GUI sidebar bar.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::Isolated => "high",
            Self::Bootstrapping | Self::Creating | Self::Syncing | Self::CatchingUp => "syncing",
            Self::Aligned => "zero",
            Self::Diverged => "medium",
        }
    }
}

/// Snapshot of alignment state. Written by HealingManager per tick, read by RPC.
#[derive(Debug, Clone)]
pub struct AlignmentSnapshot {
    pub state: AlignmentState,
    pub height: u64,
    pub peer_count: usize,
    pub highest_known: u64,
    pub progress: f64,
    pub cycles_remaining: Option<u32>,
}

impl Default for AlignmentSnapshot {
    fn default() -> Self {
        Self {
            state: AlignmentState::Isolated,
            height: 0,
            peer_count: 0,
            highest_known: 0,
            progress: 0.0,
            cycles_remaining: None,
        }
    }
}
