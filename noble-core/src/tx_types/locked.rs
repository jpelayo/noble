// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_LOCKED;

/// Locked notarization (0x06).
///
/// Metadata values and checksum are AES-256-GCM encrypted with a password.
/// The checksum field is `Hash256::ZERO`; the real checksum is stored encrypted
/// in `metadata["locked:checksum"]`. An unlocking transaction (0x07) publishes
/// the password and triggers on-chain decryption + re-indexing.
///
/// Required metadata keys:
/// - `locked:checksum` — AES-GCM ciphertext of the real document checksum (hex)
/// - `locked:salt` — 16 random bytes for key derivation (hex)
/// - `locked:nonce` — 12-byte GCM nonce (hex)
pub struct Locked;

impl TxTypeHandler for Locked {
    fn type_id(&self) -> u8 { TX_TYPE_LOCKED }
    fn name(&self) -> &'static str { "Locked" }
    fn requires_zero_checksum(&self) -> bool { true }
    fn allows_encrypted_locator(&self) -> bool { true }
    fn allows_external_attestations(&self) -> bool { true }
}
