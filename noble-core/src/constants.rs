// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Protocol constants — single source of truth (GAP-L5).

/// Maximum serialized transaction size in bytes.
pub const MAX_TX_SIZE: usize = 4_096;

/// Maximum serialized block size in bytes (4 MB).
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum number of metadata entries per transaction.
pub const MAX_METADATA_ENTRIES: usize = 16;

/// Maximum metadata key length in bytes.
pub const MAX_METADATA_KEY_LEN: usize = 64;

/// Maximum metadata value length in bytes.
pub const MAX_METADATA_VALUE_LEN: usize = 256;

/// Maximum number of additional signatures per transaction.
pub const MAX_ADDITIONAL_SIGS: usize = 32;

/// Main network chain identifier ("NOBL" in ASCII, big-endian).
pub const MAINNET_CHAIN_ID: u32 = 0x4E4F_424C;

/// Test network chain identifier ("TSTN" in ASCII, big-endian).
pub const TESTNET_CHAIN_ID: u32 = 0x5453_544E;

/// Minimum transaction fee in atomic units (0.001 NOBLE = 1000 units).
pub const MIN_TX_FEE: u64 = 1_000;

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum allowed timestamp skew into the future for transactions (seconds).
pub const MAX_TX_TIMESTAMP_SKEW: u64 = 3_600;

/// Maximum allowed block timestamp skew into the future (seconds).
pub const MAX_BLOCK_FUTURE_SKEW: u64 = 7_200;

/// Maximum allowed block timestamp skew into the past (seconds).
pub const MAX_BLOCK_PAST_SKEW: u64 = 3_600;

/// Duration of a consensus cycle in seconds (30 minutes).
pub const CYCLE_DURATION_SECS: u64 = 1_800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_ascii_encoding() {
        // "NOBL" = 0x4E 0x4F 0x42 0x4C
        assert_eq!(MAINNET_CHAIN_ID.to_be_bytes(), [0x4E, 0x4F, 0x42, 0x4C]);
        // "TSTN" = 0x54 0x53 0x54 0x4E
        assert_eq!(TESTNET_CHAIN_ID.to_be_bytes(), [0x54, 0x53, 0x54, 0x4E]);
    }

    #[test]
    fn min_fee_is_0001_noble() {
        // 0.001 NOBLE with 6 decimal places = 1000 atomic units
        assert_eq!(MIN_TX_FEE, 1_000);
    }

    #[test]
    fn block_size_is_4mb() {
        assert_eq!(MAX_BLOCK_SIZE, 4_194_304);
    }
}
