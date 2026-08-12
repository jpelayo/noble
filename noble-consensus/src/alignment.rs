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
    /// The node cannot make progress on its own and needs an operator: chain
    /// integrity failed with no intact prefix to rewind to, or sync is
    /// refusing blocks for a reason retrying cannot fix (no genesis).
    ///
    /// This outranks every other state. It exists so "halted" is decided once,
    /// by the node, rather than inferred separately by each GUI widget — the
    /// failure mode being that a stuck node renders as a busy one.
    Blocked,
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
            Self::Blocked => "Blocked",
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
            Self::Blocked => "high",
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
    /// Operator-facing explanation when `state == Blocked`. Carried alongside
    /// the state so the GUI never has to reconstruct the reason from event
    /// history it may have missed (a page opened after the event fired).
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

    #[test]
    fn blocked_has_a_label_and_the_highest_severity() {
        // Blocked must never render with a "progress" severity — the whole
        // point is that it does not look like a node making headway.
        assert_eq!(AlignmentState::Blocked.label(), "Blocked");
        assert_eq!(AlignmentState::Blocked.severity(), "high");
        assert_ne!(AlignmentState::Blocked.severity(), "syncing");
        assert_ne!(AlignmentState::Blocked.severity(), "zero");
    }

    #[test]
    fn every_state_has_a_severity() {
        // `severity()` matches exhaustively; this guards the label side and
        // documents that no state renders as untyped.
        for st in [
            AlignmentState::Isolated,
            AlignmentState::Bootstrapping,
            AlignmentState::Creating,
            AlignmentState::Syncing,
            AlignmentState::Verifying,
            AlignmentState::Aligned,
            AlignmentState::CatchingUp,
            AlignmentState::Diverged,
            AlignmentState::Blocked,
        ] {
            assert!(!st.label().is_empty());
            assert!(matches!(st.severity(), "zero" | "syncing" | "medium" | "high"));
        }
    }

    #[test]
    fn default_snapshot_is_not_blocked() {
        let snap = AlignmentSnapshot::default();
        assert!(snap.blocked_reason.is_none());
        assert_ne!(snap.state, AlignmentState::Blocked);
    }
}
