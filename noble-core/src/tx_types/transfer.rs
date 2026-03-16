// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_TRANSFER;

/// Token transfer (0x01).
///
/// Checksum must be zero. At least one output required.
pub struct Transfer;

impl TxTypeHandler for Transfer {
    fn type_id(&self) -> u8 { TX_TYPE_TRANSFER }
    fn name(&self) -> &'static str { "Transfer" }
    fn requires_zero_checksum(&self) -> bool { true }
    fn requires_outputs(&self) -> bool { true }
    fn uses_transfer_bip137_message(&self) -> bool { true }
}
