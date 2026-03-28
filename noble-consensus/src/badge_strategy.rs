// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Automatic badge voting strategies.
//!
//! Operators configure how their node auto-votes on badge proposals (grant/revoke).
//! Strategies eliminate the need for manual approval of every badge proposal.

use serde::{Deserialize, Serialize};

/// Strategy for auto-voting on badge GRANT proposals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BadgeApprovalStrategy {
    /// Auto-vote YES on every grant proposal.
    AlwaysApprove,
    /// YES if the candidate has been seen online for at least `min_days` days.
    ApproveIfSeen { min_days: u32 },
    /// Auto-vote NO on every grant proposal.
    AlwaysReject,
    /// NO if the candidate has accumulated any ban points.
    RejectIfBanned,
    /// Watch real-time tally; vote with majority. Can recast if tally flips.
    FollowTally,
    /// YES only if the proposer is in the trusted validator list.
    ApproveIfProposedBy { validators: Vec<String> },
    /// No auto-vote; operator must vote manually via RPC/GUI.
    Manual,
}

/// Strategy for auto-voting on badge REVOCATION proposals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BadgeRevocationStrategy {
    /// Auto-vote YES on every revocation proposal.
    AlwaysRevoke,
    /// Auto-vote NO (protect all badge holders).
    AlwaysRejectRevocation,
    /// YES if the target has been revoked before or has >= `min_offenses` ban events.
    RevokeIfRepeatOffender { min_offenses: u32 },
    /// YES only if the proposer is in the trusted validator list.
    RevokeIfProposedBy { validators: Vec<String> },
    /// Watch real-time tally; vote with majority. Can recast if tally flips.
    FollowTally,
    /// No auto-vote; operator must vote manually via RPC/GUI.
    Manual,
}

impl Default for BadgeApprovalStrategy {
    fn default() -> Self {
        Self::ApproveIfSeen { min_days: 7 }
    }
}

impl Default for BadgeRevocationStrategy {
    fn default() -> Self {
        Self::RevokeIfRepeatOffender { min_offenses: 3 }
    }
}

/// Evaluate whether to auto-vote on a badge grant proposal.
///
/// Returns `Some(true)` for YES, `Some(false)` for NO, `None` for abstain/manual.
pub fn evaluate_approval(
    strategy: &BadgeApprovalStrategy,
    candidate_first_seen: Option<u64>,
    candidate_has_bans: bool,
    proposer_key_hex: &str,
    _current_tally_for: usize,
    _current_tally_against: usize,
    _total_eligible: usize,
    now: u64,
) -> Option<bool> {
    match strategy {
        BadgeApprovalStrategy::AlwaysApprove => Some(true),
        BadgeApprovalStrategy::AlwaysReject => Some(false),
        BadgeApprovalStrategy::RejectIfBanned => {
            if candidate_has_bans { Some(false) } else { Some(true) }
        }
        BadgeApprovalStrategy::ApproveIfSeen { min_days } => {
            if let Some(first_seen) = candidate_first_seen {
                let days_online = (now.saturating_sub(first_seen)) / 86400;
                if days_online >= *min_days as u64 { Some(true) } else { None }
            } else {
                None // haven't seen this candidate
            }
        }
        BadgeApprovalStrategy::ApproveIfProposedBy { validators } => {
            if validators.iter().any(|v| v == proposer_key_hex) {
                Some(true)
            } else {
                None // proposer not in trusted list — abstain
            }
        }
        BadgeApprovalStrategy::FollowTally => {
            if _total_eligible == 0 { return None; }
            if _current_tally_for > _current_tally_against {
                Some(true)
            } else if _current_tally_against > _current_tally_for {
                Some(false)
            } else {
                None // tied — wait
            }
        }
        BadgeApprovalStrategy::Manual => None,
    }
}

/// Evaluate whether to auto-vote on a badge revocation proposal.
pub fn evaluate_revocation(
    strategy: &BadgeRevocationStrategy,
    target_previous_revocations: u32,
    target_ban_count: u32,
    proposer_key_hex: &str,
    _current_tally_for: usize,
    _current_tally_against: usize,
    _total_eligible: usize,
) -> Option<bool> {
    match strategy {
        BadgeRevocationStrategy::AlwaysRevoke => Some(true),
        BadgeRevocationStrategy::AlwaysRejectRevocation => Some(false),
        BadgeRevocationStrategy::RevokeIfRepeatOffender { min_offenses } => {
            let total_offenses = target_previous_revocations + target_ban_count;
            if total_offenses >= *min_offenses { Some(true) } else { None }
        }
        BadgeRevocationStrategy::RevokeIfProposedBy { validators } => {
            if validators.iter().any(|v| v == proposer_key_hex) {
                Some(true)
            } else {
                None
            }
        }
        BadgeRevocationStrategy::FollowTally => {
            if _total_eligible == 0 { return None; }
            if _current_tally_for > _current_tally_against {
                Some(true)
            } else if _current_tally_against > _current_tally_for {
                Some(false)
            } else {
                None
            }
        }
        BadgeRevocationStrategy::Manual => None,
    }
}
