// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

use super::TxTypeHandler;
use crate::constants::TX_TYPE_NOTARIZATION;

/// Document registration (0x00).
///
/// Requires a non-zero checksum (SHA-256 of the document). Allows
/// encrypted locators, external attestations, and version chain metadata.
pub struct Notarization;

impl TxTypeHandler for Notarization {
    fn type_id(&self) -> u8 { TX_TYPE_NOTARIZATION }
    fn name(&self) -> &'static str { "Notarization" }
    fn requires_checksum(&self) -> bool { true }
    fn allows_encrypted_locator(&self) -> bool { true }
    fn allows_external_attestations(&self) -> bool { true }
    fn validates_version_chain(&self) -> bool { true }
    fn needs_notarization_indexing(&self) -> bool { true }
}
