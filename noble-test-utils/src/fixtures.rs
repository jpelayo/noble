// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Test fixture builders for NOBLE protocol types.
//!
//! Provides builder-pattern constructors for creating test instances of
//! `Transaction`, `Block`, `BlockHeader`, `SignatureEnvelope`, etc.
//! Stubs — will be populated when noble-core types are implemented in Sprint 1.

/// Placeholder: will return a valid test transaction once noble-core types exist.
pub fn sample_tx_id() -> [u8; 32] {
    [0xAB; 32]
}

/// Placeholder: will return a test block hash once noble-core types exist.
pub fn sample_block_hash() -> [u8; 32] {
    [0xCD; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_fixtures_are_deterministic() {
        assert_eq!(sample_tx_id(), sample_tx_id());
        assert_eq!(sample_block_hash(), sample_block_hash());
        assert_ne!(sample_tx_id(), sample_block_hash());
    }
}
