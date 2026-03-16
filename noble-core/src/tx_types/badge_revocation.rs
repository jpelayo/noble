// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_BADGE_REVOCATION;

/// Badge revocation (0x05).
///
/// Checksum must be zero.
pub struct BadgeRevocation;

impl TxTypeHandler for BadgeRevocation {
    fn type_id(&self) -> u8 { TX_TYPE_BADGE_REVOCATION }
    fn name(&self) -> &'static str { "Badge Revocation" }
    fn requires_zero_checksum(&self) -> bool { true }
}
