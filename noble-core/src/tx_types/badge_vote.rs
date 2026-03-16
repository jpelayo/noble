// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_BADGE_VOTE;

/// Badge vote — approve or reject a proposal (0x04).
///
/// Checksum must be zero. Metadata carries proposal_hash and vote.
pub struct BadgeVote;

impl TxTypeHandler for BadgeVote {
    fn type_id(&self) -> u8 { TX_TYPE_BADGE_VOTE }
    fn name(&self) -> &'static str { "Badge Vote" }
    fn requires_zero_checksum(&self) -> bool { true }
}
