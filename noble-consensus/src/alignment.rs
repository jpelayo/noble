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
    /// height > 0, behind the highest known peer tip beyond the tolerance.
    Syncing,
    /// Connected, but no peer has announced a chain tip yet — alignment
    /// cannot be confirmed. Evidence-free is NOT the same as aligned: this
    /// state exists so a freshly (re)connected or post-reset node never
    /// claims "Aligned" on zero information. With status solicitation on
    /// connect it should last seconds.
    Verifying,
    /// On the majority chain (> 50% of known peers agree).
    Aligned,
    /// Behind peers that share our chain_id — sequential catch-up in progress.
    CatchingUp,
    /// NOT on the majority chain, or healing fork dwell timer running.
    Diverged,
    // NOTE: there is deliberately no `Blocked` state.
    //
    // A chain failure is a protocol event and must be resolved by protocol
    // rules; no node may halt and wait for a human. Every condition that once
    // produced `Blocked` — unrepairable integrity failure, missing genesis, an
    // unacceptable peer genesis, a refused cross-chain adoption — now resolves
    // itself in `HealingManager`. Do not reintroduce a halting state here.
}

impl AlignmentState {
    /// Display label for the GUI sidebar and RPC responses.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Isolated => "Isolated",
            Self::Bootstrapping => "Bootstrapping",
            Self::Creating => "Creating",
            Self::Syncing => "Syncing",
            Self::Verifying => "Verifying",
            Self::Aligned => "Aligned",
            Self::CatchingUp => "Catching Up",
            Self::Diverged => "Diverged",
        }
    }

    /// CSS severity class for the GUI sidebar bar.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::Isolated => "high",
            Self::Bootstrapping | Self::Creating | Self::Syncing | Self::CatchingUp
            | Self::Verifying => "syncing",
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
    /// Retained only so existing API clients keep deserialising `getSyncStatus`.
    /// Always `None` — the node no longer has a halted state to explain.
    pub blocked_reason: Option<String>,
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
            blocked_reason: None,
        }
    }
}


#[cfg(test)]
mod blocked_tests {
    use super::*;

    /// R6: the halting state must stay gone.
    ///
    /// `label()` and `severity()` match exhaustively, so any reintroduced
    /// variant breaks compilation here — but this pins the *intent* in a place
    /// a reader will find, rather than leaving it to a compiler error.
    #[test]
    fn no_state_is_a_halted_operator_gated_state() {
        for st in ALL_STATES {
            assert_ne!(
                st.label(),
                "Blocked",
                "a chain failure is resolved by protocol, never by an operator"
            );
        }
    }

    const ALL_STATES: [AlignmentState; 8] = [
        AlignmentState::Isolated,
        AlignmentState::Bootstrapping,
        AlignmentState::Creating,
        AlignmentState::Syncing,
        AlignmentState::Verifying,
        AlignmentState::Aligned,
        AlignmentState::CatchingUp,
        AlignmentState::Diverged,
    ];

    #[test]
    fn every_state_has_a_severity() {
        // `severity()` matches exhaustively; this guards the label side and
        // documents that no state renders as untyped.
        for st in ALL_STATES {
            assert!(!st.label().is_empty());
            assert!(matches!(st.severity(), "zero" | "syncing" | "medium" | "high"));
        }
    }

    #[test]
    fn snapshot_never_carries_a_blocked_reason() {
        let snap = AlignmentSnapshot::default();
        assert!(snap.blocked_reason.is_none());
    }
}
