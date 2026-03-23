// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_COINBASE;

/// Block Reward (0x10).
///
/// Single null input. Output carries `subsidy_at_height(h)` to the validator.
/// Not submitted by users — created by the consensus engine.
/// Always block transaction index 0.
pub struct Coinbase;

impl TxTypeHandler for Coinbase {
    fn type_id(&self) -> u8 { TX_TYPE_COINBASE }
    fn name(&self) -> &'static str { "Block Reward" }
    fn is_coinbase(&self) -> bool { true }
}
