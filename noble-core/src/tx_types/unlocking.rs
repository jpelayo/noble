// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_UNLOCKING;

/// Unlocking transaction (0x07).
///
/// References a locked transaction (0x06) by tx_id and publishes the
/// decryption password. On commit, the node decrypts the locked tx's
/// encrypted fields and re-indexes them (checksum, version chain, publisher).
///
/// Required metadata keys:
/// - `unlock:txid` — hex tx_id of the locked transaction (64 chars)
/// - `unlock:password` — the decryption password (raw UTF-8 bytes, NOT hex-encoded)
///
/// The publisher must be the same signer as the locked transaction.
pub struct Unlocking;

impl TxTypeHandler for Unlocking {
    fn type_id(&self) -> u8 { TX_TYPE_UNLOCKING }
    fn name(&self) -> &'static str { "Unlocking" }
    fn requires_checksum(&self) -> bool { true }
    fn needs_notarization_indexing(&self) -> bool { true }
}
