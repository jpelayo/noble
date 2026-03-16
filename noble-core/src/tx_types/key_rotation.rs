// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_KEY_ROTATION;

/// Validator key rotation (0x02).
///
/// Checksum must be zero. Outputs required (output[0] carries the new key).
pub struct KeyRotation;

impl TxTypeHandler for KeyRotation {
    fn type_id(&self) -> u8 { TX_TYPE_KEY_ROTATION }
    fn name(&self) -> &'static str { "Key Rotation" }
    fn requires_zero_checksum(&self) -> bool { true }
    fn requires_outputs(&self) -> bool { true }
}
