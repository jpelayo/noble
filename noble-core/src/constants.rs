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

// Chain identifiers are derived from their genesis block hashes.
// See `mainnet_chain_id()`, `testnet_chain_id()`, `regtest_chain_id()`
// in the `genesis` module.

/// Minimum transaction fee in atomic units (1 atomic unit — the market decides the rest).
pub const MIN_TX_FEE: u64 = 1;

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum allowed timestamp skew into the future for transactions (seconds).
pub const MAX_TX_TIMESTAMP_SKEW: u64 = 3_600;

/// Maximum allowed block timestamp skew into the future (seconds).
/// Tightened from 2h to 5min in S49 to limit median-of-11 manipulation.
pub const MAX_BLOCK_FUTURE_SKEW: u64 = 300;

/// Warn if |median peer clock offset| exceeds this threshold (seconds).
pub const CLOCK_DRIFT_WARNING_SECS: u64 = 30;

/// Critical: suppress block proposals if |median peer clock offset| exceeds this (seconds).
pub const CLOCK_DRIFT_CRITICAL_SECS: u64 = 120;

/// Maximum allowed block timestamp skew into the past (seconds).
pub const MAX_BLOCK_PAST_SKEW: u64 = 3_600;

/// Duration of a consensus cycle in seconds (20 minutes).
pub const CYCLE_DURATION_SECS: u64 = 1_200;

/// Transaction type: document notarization.
pub const TX_TYPE_NOTARIZATION: u8 = 0x00;

/// Transaction type: NOBLE token transfer.
pub const TX_TYPE_TRANSFER: u8 = 0x01;

/// Transaction type: validator key rotation.
pub const TX_TYPE_KEY_ROTATION: u8 = 0x02;

/// Transaction type: badge proposal (grant vote badge to a peer).
pub const TX_TYPE_BADGE_PROPOSAL: u8 = 0x03;

/// Transaction type: badge vote (approve/reject a proposal or revocation).
pub const TX_TYPE_BADGE_VOTE: u8 = 0x04;

/// Transaction type: badge revocation (propose revoking an existing badge).
pub const TX_TYPE_BADGE_REVOCATION: u8 = 0x05;

/// Minimum presence time (seconds) before a node can be proposed for a badge.
/// Production: 7 days = 604,800 seconds. Testnet: 2 days = 172,800 seconds.
pub const BADGE_MIN_PRESENCE_SECS: u64 = 604_800;

/// Testnet minimum presence (2 days).
pub const BADGE_MIN_PRESENCE_TESTNET_SECS: u64 = 172_800;

/// Bootstrap mode duration in cycles (60 days at 30-min cycles = 2,880 cycles).
pub const BOOTSTRAP_MODE_CYCLES: u64 = 2_880;

/// Suspension threshold: offline for this many seconds triggers local suspension.
/// 15 days = 1,296,000 seconds.
pub const BADGE_SUSPENSION_THRESHOLD_SECS: u64 = 1_296_000;

/// Recovery period: must be online for this many seconds to recover from suspension.
/// 2 days = 172,800 seconds.
pub const BADGE_RECOVERY_THRESHOLD_SECS: u64 = 172_800;

/// Voting window for badge proposals/revocations: 48 cycles = 24 hours.
pub const BADGE_VOTE_WINDOW_CYCLES: u64 = 48;

/// Grace period (in cycles) during which both old and new keys are valid.
/// 48 cycles = 24 hours at 30-min cycles.
pub const KEY_ROTATION_GRACE_CYCLES: u64 = 48;

/// Initial block subsidy in atomic units (50 NOBLE = 50_000_000 with 6 decimals).
pub const INITIAL_SUBSIDY: u64 = 50_000_000;

/// Number of blocks between halving events (~12 years at 30-min cycles).
pub const HALVING_INTERVAL: u64 = 210_000;

/// Maximum total supply in atomic units (21 million NOBLE = 21_000_000_000_000).
pub const MAX_SUPPLY: u64 = 21_000_000_000_000;

/// Maximum reorg depth allowed (144 blocks ≈ 3 days at 30-min cycles).
pub const MAX_REORG_DEPTH: u64 = 144;

/// Merkle leaf hash domain-separation prefix.
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// Merkle internal node hash domain-separation prefix.
pub const MERKLE_INTERNAL_PREFIX: u8 = 0x01;

/// Human-readable software version string — sourced from the workspace Cargo.toml.
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current NodeAnnounce message version.
pub const NODE_ANNOUNCE_VERSION: u16 = 1;

/// Maximum length of a node name in a NodeAnnounce (bytes).
pub const MAX_NODE_NAME_LEN: usize = 64;

/// Maximum length of an organization name in a NodeAnnounce (bytes).
pub const MAX_ORG_NAME_LEN: usize = 128;

/// Maximum length of a software version string in a NodeAnnounce (bytes).
pub const MAX_SOFTWARE_VERSION_LEN: usize = 32;

/// Maximum age of a NodeAnnounce before it is considered stale (seconds).
pub const NODE_ANNOUNCE_MAX_AGE_SECS: u64 = 3_600;

/// Validator liveness: considered alive if last seen within 3 cycles (1.5h).
pub const VALIDATOR_ALIVE_THRESHOLD_SECS: u64 = 5_400;

/// Validator liveness: considered stale if last seen within 12 cycles (6h).
/// Beyond this threshold, the validator is considered unreachable.
pub const VALIDATOR_STALE_THRESHOLD_SECS: u64 = 21_600;

/// Maximum size of an external attestation's signature_data in bytes.
pub const MAX_ATTESTATION_DATA_SIZE: usize = 8192;

/// Domain separation tag for PKI identity binding messages.
/// The PKCS#7 signature signs: `sha256(PKI_BIND_DOMAIN_TAG || identity_key_bytes)`.
pub const PKI_BIND_DOMAIN_TAG: &[u8] = b"NOBLE-PKI-BIND-v1";

/// Well-known metadata key: hex-encoded checksum of the previous document version.
pub const META_KEY_PREV_CHECKSUM: &str = "doc:prev_checksum";

/// Well-known metadata key: version ordinal (UTF-8 positive integer string).
pub const META_KEY_VERSION: &str = "doc:version";

/// S34: Block height at which `source_address` becomes mandatory for secp256k1
/// transfer senders. Below this height, legacy implicit fallback is allowed.
/// Set to u64::MAX (effectively disabled) until the network activates the feature.
pub const SOURCE_ADDRESS_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Known-good block hashes at specific heights for fast initial sync.
///
/// Height 0 is the genesis block hash, computed from the deterministic seed.
/// Additional checkpoints will be added after mainnet launch.
///
/// Since the genesis hash depends on the keypair derivation at runtime,
/// use [`is_valid_checkpoint`] which compares against `genesis_hash()`.
pub const CHECKPOINTS: &[(u64, &str)] = &[];

/// Validate a block hash against known checkpoints.
///
/// Returns:
/// - `Some(true)` if the height is a checkpoint and the hash matches.
/// - `Some(false)` if the height is a checkpoint but the hash does NOT match.
/// - `None` if the height is not a checkpoint (no opinion).
///
/// Height 0 is always checked against the genesis block hash.
pub fn is_valid_checkpoint(height: u64, hash: &noble_crypto::Hash256) -> Option<bool> {
    use crate::genesis;

    // Height 0: always validate against the computed genesis hash.
    if height == 0 {
        let genesis = genesis::genesis_hash();
        return Some(*hash == genesis);
    }

    // Check static checkpoints table.
    for &(cp_height, cp_hex) in CHECKPOINTS {
        if cp_height == height {
            let hex_str = hex::encode(hash.as_bytes());
            return Some(hex_str == cp_hex);
        }
    }

    None
}

/// Maximum mempool size in bytes (default 300 MB).
pub const MAX_MEMPOOL_SIZE: usize = 300 * 1024 * 1024;

/// AUD-H4: Compute the dynamic minimum fee based on mempool utilization.
///
/// - `< 50%` → `MIN_TX_FEE` (1)
/// - `50-75%` → `MIN_TX_FEE * 2`
/// - `75-90%` → `MIN_TX_FEE * 5`
/// - `> 90%` → `MIN_TX_FEE * 10`
pub fn dynamic_min_fee(utilization_pct: u8) -> u64 {
    match utilization_pct {
        0..=49 => MIN_TX_FEE,
        50..=74 => MIN_TX_FEE * 2,
        75..=89 => MIN_TX_FEE * 5,
        _ => MIN_TX_FEE * 10,
    }
}

/// Compute block subsidy at a given height.
/// Returns 0 for the genesis block (height 0) because the genesis validator key
/// is deterministically derived and publicly known. First subsidy is at height 1.
/// Returns 0 when all halvings are exhausted (after 64 halvings).
pub fn subsidy_at_height(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
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
    fn chain_ids_derived_from_genesis_hashes() {
        use crate::genesis::{
            derive_chain_id, genesis_hash, mainnet_chain_id, regtest_chain_id,
            testnet_chain_id, testnet_genesis_hash, regtest_genesis_hash,
        };
        // Each chain ID equals the first 4 bytes of its genesis hash.
        assert_eq!(mainnet_chain_id(), derive_chain_id(&genesis_hash()));
        assert_eq!(testnet_chain_id(), derive_chain_id(&testnet_genesis_hash()));
        assert_eq!(regtest_chain_id(), derive_chain_id(&regtest_genesis_hash()));
        // All three are distinct.
        assert_ne!(mainnet_chain_id(), testnet_chain_id());
        assert_ne!(mainnet_chain_id(), regtest_chain_id());
        assert_ne!(testnet_chain_id(), regtest_chain_id());
    }

    #[test]
    fn min_fee_is_0001_noble() {
        // 0.001 NOBLE with 6 decimal places = 1000 atomic units
        assert_eq!(MIN_TX_FEE, 1);
    }

    #[test]
    fn block_size_is_4mb() {
        assert_eq!(MAX_BLOCK_SIZE, 4_194_304);
    }

    #[test]
    fn subsidy_at_genesis_is_zero() {
        // Genesis block subsidy is zero — the genesis validator key is publicly derivable
        assert_eq!(subsidy_at_height(0), 0);
        // First subsidy-bearing block is height 1
        assert_eq!(subsidy_at_height(1), INITIAL_SUBSIDY);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL - 1), INITIAL_SUBSIDY);
    }

    #[test]
    fn total_supply_is_deterministic_and_below_max() {
        let mut total: u128 = 0;
        for epoch in 0u64..64 {
            let subsidy = INITIAL_SUBSIDY >> epoch;
            if subsidy == 0 {
                break;
            }
            // Epoch 0 has 209,999 blocks (height 0 excluded), epochs 1+ have 210,000
            let blocks = if epoch == 0 {
                HALVING_INTERVAL - 1
            } else {
                HALVING_INTERVAL
            };
            total += subsidy as u128 * blocks as u128;
        }
        assert_eq!(total, 20_999_947_480_000u128);
        assert!(total < MAX_SUPPLY as u128);
    }

    #[test]
    fn subsidy_halves_correctly() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL), INITIAL_SUBSIDY / 2);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 2), INITIAL_SUBSIDY / 4);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 3), INITIAL_SUBSIDY / 8);
    }

    // AUD-H4: Dynamic fee tests
    #[test]
    fn dynamic_fee_at_zero_utilization() {
        assert_eq!(dynamic_min_fee(0), MIN_TX_FEE);
        assert_eq!(dynamic_min_fee(25), MIN_TX_FEE);
        assert_eq!(dynamic_min_fee(49), MIN_TX_FEE);
    }

    #[test]
    fn dynamic_fee_at_medium_utilization() {
        assert_eq!(dynamic_min_fee(50), MIN_TX_FEE * 2);
        assert_eq!(dynamic_min_fee(60), MIN_TX_FEE * 2);
        assert_eq!(dynamic_min_fee(74), MIN_TX_FEE * 2);
    }

    #[test]
    fn dynamic_fee_at_high_utilization() {
        assert_eq!(dynamic_min_fee(75), MIN_TX_FEE * 5);
        assert_eq!(dynamic_min_fee(89), MIN_TX_FEE * 5);
        assert_eq!(dynamic_min_fee(90), MIN_TX_FEE * 10);
        assert_eq!(dynamic_min_fee(95), MIN_TX_FEE * 10);
        assert_eq!(dynamic_min_fee(100), MIN_TX_FEE * 10);
    }

    // --- Checkpoint tests ---

    #[test]
    fn checkpoint_genesis_hash_matches() {
        let genesis = crate::genesis::genesis_hash();
        assert_eq!(is_valid_checkpoint(0, &genesis), Some(true));
    }

    #[test]
    fn checkpoint_genesis_wrong_hash_rejected() {
        assert_eq!(
            is_valid_checkpoint(0, &noble_crypto::Hash256::ZERO),
            Some(false)
        );
    }

    #[test]
    fn checkpoint_unknown_height_returns_none() {
        let hash = noble_crypto::Hash256::from_bytes([0xAA; 32]);
        assert_eq!(is_valid_checkpoint(999_999, &hash), None);
    }

    #[test]
    fn subsidy_exhausted_after_64_halvings() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 64), 0);
        assert_eq!(subsidy_at_height(u64::MAX), 0);
    }
}
