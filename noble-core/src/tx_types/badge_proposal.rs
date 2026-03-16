// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_BADGE_PROPOSAL;

/// Badge proposal — grant or revoke (0x03).
///
/// Checksum must be zero. Metadata carries target_pubkey, proposal_type, reason.
pub struct BadgeProposal;

impl TxTypeHandler for BadgeProposal {
    fn type_id(&self) -> u8 { TX_TYPE_BADGE_PROPOSAL }
    fn name(&self) -> &'static str { "Badge Proposal" }
    fn requires_zero_checksum(&self) -> bool { true }
}
