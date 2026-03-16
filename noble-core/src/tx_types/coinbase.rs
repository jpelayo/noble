// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_COINBASE;

/// Block reward + collected fees (0x10).
///
/// Single null input. Outputs carry subsidy + fee distribution.
/// Not submitted by users — created by the consensus engine.
pub struct Coinbase;

impl TxTypeHandler for Coinbase {
    fn type_id(&self) -> u8 { TX_TYPE_COINBASE }
    fn name(&self) -> &'static str { "Coinbase" }
    fn is_coinbase(&self) -> bool { true }
}
