// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_FEE;

/// Fee Distribution (0x11).
///
/// Carries collected transaction fees to the validator and gateways.
/// Single null input (`COINBASE_PREVOUT`). Outputs split between
/// validator fee share and gateway fee shares.
/// Not submitted by users — created by the consensus engine.
/// Omitted from blocks with zero total fees.
pub struct FeeDistribution;

impl TxTypeHandler for FeeDistribution {
    fn type_id(&self) -> u8 { TX_TYPE_FEE }
    fn name(&self) -> &'static str { "Fee Distribution" }
    fn is_coinbase(&self) -> bool { true }
}
