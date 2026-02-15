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

/// Transaction type: document notarization.
pub const TX_TYPE_NOTARIZATION: u8 = 0x00;

/// Transaction type: NOBLE token transfer.
pub const TX_TYPE_TRANSFER: u8 = 0x01;

/// Transaction type: validator key rotation.
pub const TX_TYPE_KEY_ROTATION: u8 = 0x02;

/// Grace period (in cycles) during which both old and new keys are valid.
/// 48 cycles = 24 hours at 30-min cycles.
pub const KEY_ROTATION_GRACE_CYCLES: u64 = 48;

/// Initial block subsidy in atomic units (50 NOBLE = 50_000_000 with 6 decimals).
pub const INITIAL_SUBSIDY: u64 = 50_000_000;

/// Number of blocks between halving events (~12 years at 30-min cycles).
pub const HALVING_INTERVAL: u64 = 210_000;

/// Human-readable software version string.
pub const SOFTWARE_VERSION: &str = "0.1.0";

/// Current NodeAnnounce message version.
pub const NODE_ANNOUNCE_VERSION: u16 = 1;

/// Maximum length of a node name in a NodeAnnounce (bytes).
pub const MAX_NODE_NAME_LEN: usize = 64;

/// Maximum length of an organization name in a NodeAnnounce (bytes).
pub const MAX_ORG_NAME_LEN: usize = 128;

/// Maximum age of a NodeAnnounce before it is considered stale (seconds).
pub const NODE_ANNOUNCE_MAX_AGE_SECS: u64 = 3_600;

/// Validator liveness: considered alive if last seen within 3 cycles (1.5h).
pub const VALIDATOR_ALIVE_THRESHOLD_SECS: u64 = 5_400;

/// Validator liveness: considered stale if last seen within 12 cycles (6h).
/// Beyond this threshold, the validator is considered unreachable.
pub const VALIDATOR_STALE_THRESHOLD_SECS: u64 = 21_600;

/// Compute block subsidy at a given height.
/// Returns 0 when all halvings are exhausted (after 64 halvings).
pub fn subsidy_at_height(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

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

    #[test]
    fn subsidy_at_genesis() {
        assert_eq!(subsidy_at_height(0), INITIAL_SUBSIDY);
        assert_eq!(subsidy_at_height(1), INITIAL_SUBSIDY);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL - 1), INITIAL_SUBSIDY);
    }

    #[test]
    fn subsidy_halves_correctly() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL), INITIAL_SUBSIDY / 2);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 2), INITIAL_SUBSIDY / 4);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 3), INITIAL_SUBSIDY / 8);
    }

    #[test]
    fn subsidy_exhausted_after_64_halvings() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 64), 0);
        assert_eq!(subsidy_at_height(u64::MAX), 0);
    }
}
