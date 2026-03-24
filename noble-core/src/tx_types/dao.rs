// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_DAO;

/// DAO governance poll — create or vote (0x12).
///
/// Checksum must be zero. Metadata carries dao:action, dao:question or dao:poll_id + dao:vote.
/// Badge holders only (or any validator during bootstrap mode).
pub struct Dao;

impl TxTypeHandler for Dao {
    fn type_id(&self) -> u8 { TX_TYPE_DAO }
    fn name(&self) -> &'static str { "DAO Poll" }
    fn requires_zero_checksum(&self) -> bool { true }
}
