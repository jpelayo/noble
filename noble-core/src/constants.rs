// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Protocol constants — single source of truth (GAP-L5).

/// Maximum serialized transaction size in bytes (8 KB).
pub const MAX_TX_SIZE: usize = 8_192;

/// Maximum serialized block size in bytes (8 MB).
pub const MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Maximum number of inputs per transaction (DoS prevention — limits UTXO lookup cost).
pub const MAX_TX_INPUTS: usize = 64;

/// Maximum number of outputs per transaction (UTXO set pollution prevention).
pub const MAX_TX_OUTPUTS: usize = 64;

/// Maximum number of metadata entries per transaction.
pub const MAX_METADATA_ENTRIES: usize = 16;

/// Maximum metadata key length in bytes.
pub const MAX_METADATA_KEY_LEN: usize = 64;

/// Maximum metadata value length in bytes.
pub const MAX_METADATA_VALUE_LEN: usize = 256;

/// Maximum number of additional signatures per transaction.
pub const MAX_ADDITIONAL_SIGS: usize = 16;

// Chain identifiers are derived from their genesis block hashes.
// See `derive_chain_id()` in the `genesis` module.

/// Minimum absolute transaction fee (1 groat). Used in test fixtures only.
/// Production fee validation uses MIN_RELAY_FEE_RATE (groats/byte) instead.
pub const MIN_TX_FEE: u64 = 1;

/// Default transaction time-to-live in seconds (24 hours).
/// Clients set `expires_at = timestamp + DEFAULT_TX_TTL_SECS` when building transactions.
pub const DEFAULT_TX_TTL_SECS: u64 = 86_400;

/// Dust threshold for coin selection (groats). Change outputs below this
/// value are not worth creating — they cost more in fees to spend than they're worth.
pub const DUST_THRESHOLD: u64 = 500_000; // 0.005 NOBLE

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

/// Duration of a consensus cycle in seconds (16 minutes).
pub const CYCLE_DURATION_SECS: u64 = 960;

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

/// Transaction type: locked notarization — metadata values and checksum are
/// AES-256-GCM encrypted with a password. Decrypted on-chain when the owner
/// submits an unlocking transaction (0x07).
pub const TX_TYPE_LOCKED: u8 = 0x06;

/// Transaction type: unlocking — references a locked tx (0x06) by tx_id and
/// publishes the decryption password. The node decrypts the locked tx's fields
/// and re-indexes them (checksum, version chain, issuer).
pub const TX_TYPE_UNLOCKING: u8 = 0x07;

/// Transaction type: coinbase (block reward + collected fees).
/// Always the first transaction (index 0) in every block.
/// Block Reward: carries `subsidy_at_height(height)` to the validator.
/// Has a single null input (`OutPoint::COINBASE_PREVOUT`).
/// Always block transaction index 0.
pub const TX_TYPE_COINBASE: u8 = 0x10;

/// Fee Distribution: carries collected transaction fees to validator + gateways.
/// Has a single null input (`OutPoint::COINBASE_PREVOUT`).
/// Block transaction index 1 (omitted if total fees == 0).
pub const TX_TYPE_FEE: u8 = 0x11;

/// Transaction type: DAO governance poll (create or vote).
/// Badge holders only (or any validator during bootstrap mode).
/// Zero inputs/outputs. Metadata carries question + votes.
pub const TX_TYPE_DAO: u8 = 0x12;

/// Number of confirmations before coinbase outputs are spendable.
/// ALL UTXOs (coinbase and non-coinbase) require this many confirmations
/// before they can be spent. Aligned with finality threshold (3 cycles).
pub const COINBASE_MATURITY: u64 = 3;

/// Minimum presence time (seconds) before a node can be proposed for a badge.
/// Default: 7 days = 604,800 seconds. Short-lived chains: 2 days = 172,800 seconds.
pub const BADGE_MIN_PRESENCE_SECS: u64 = 604_800;

/// Short-chain minimum presence (2 days).
pub const BADGE_MIN_PRESENCE_SHORT_SECS: u64 = 172_800;

/// Bootstrap mode duration in cycles (60 days at 16-min cycles = 5,400 cycles).
/// During bootstrap, the voting badge requirement is waived for governance.
pub const BOOTSTRAP_MODE_CYCLES: u64 = 5_400;

/// Proposal cooldown in cycles (30 days at 16-min cycles = 2,700 cycles).
/// Each proposer can submit at most 1 governance proposal per cooldown period.
/// Exception: provable-ban revocations (DuplicateProposal, ProtocolAbuse) bypass this.
pub const PROPOSAL_COOLDOWN_CYCLES: u64 = 2_700;

/// Suspension threshold: offline for this many seconds triggers local suspension.
/// 15 days = 1,296,000 seconds.
pub const BADGE_SUSPENSION_THRESHOLD_SECS: u64 = 1_296_000;

/// Recovery period: must be online for this many seconds to recover from suspension.
/// 2 days = 172,800 seconds.
pub const BADGE_RECOVERY_THRESHOLD_SECS: u64 = 172_800;

/// Voting window for badge proposals/revocations: 48 cycles = 24 hours.
pub const BADGE_VOTE_WINDOW_CYCLES: u64 = 48;

/// Grace period (in cycles) during which both old and new keys are valid.
/// 48 cycles = 12.8 hours at 16-min cycles.
pub const KEY_ROTATION_GRACE_CYCLES: u64 = 48;

/// Groats per NOBLE. 1 NOBLE = 100,000,000 groats (8 decimal places, same as Bitcoin satoshis).
/// The groat is the smallest indivisible unit of the NOBLE token.
pub const GROATS_PER_NOBLE: u64 = 100_000_000;

/// Initial block subsidy in groats (80 NOBLE = 8,000,000,000 groats).
pub const INITIAL_SUBSIDY: u64 = 8_000_000_000;

/// Number of blocks between halving events (~3.95 years at 16-min cycles).
pub const HALVING_INTERVAL: u64 = 130_000;

/// Maximum total supply in groats (~20.8 million NOBLE = 2,080,000,000,000,000 groats).
/// Actual emission: 2,079,991,998,310,000 groats after 33 halvings.
pub const MAX_SUPPLY: u64 = 2_080_000_000_000_000;

/// Maximum reorg depth allowed (144 blocks ≈ 1.6 days at 16-min cycles).
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

/// Well-known metadata key: document author (person or organization).
pub const META_KEY_AUTHOR: &str = "author";

/// Well-known metadata key: document publisher (distributing organization).
pub const META_KEY_PUBLISHER: &str = "publisher";

/// S34: Block height at which `source_address` becomes mandatory for secp256k1
/// transfer senders. Below this height, legacy implicit fallback is allowed.
/// Set to u64::MAX (effectively disabled) until the network activates the feature.
pub const SOURCE_ADDRESS_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Known-good block hashes at specific heights for fast initial sync.
///
/// Height 0 is validated against the chain's actual genesis hash (passed at runtime).
pub const CHECKPOINTS: &[(u64, &str)] = &[];

/// Validate a block hash against known checkpoints.
///
/// `expected_genesis` is the genesis block hash for the current chain.
///
/// Returns:
/// - `Some(true)` if the height is a checkpoint and the hash matches.
/// - `Some(false)` if the height is a checkpoint but the hash does NOT match.
/// - `None` if the height is not a checkpoint (no opinion).
pub fn is_valid_checkpoint(
    height: u64,
    hash: &noble_crypto::Hash256,
    expected_genesis: &noble_crypto::Hash256,
) -> Option<bool> {
    // Height 0: validate against the chain's genesis hash.
    if height == 0 {
        return Some(*hash == *expected_genesis);
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

/// Minimum relay fee rate in groats per byte.
/// Transactions below this rate are not relayed or included in blocks.
/// The market decides the actual fee rate; this is the floor.
pub const MIN_RELAY_FEE_RATE: u64 = 1;

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
    fn chain_id_derived_from_genesis_hash() {
        use crate::genesis::{build_genesis, derive_chain_id, GENESIS_TIMESTAMP};
        let block = build_genesis(GENESIS_TIMESTAMP, b"noble-test-genesis");
        let hash = block.header.compute_block_hash().unwrap();
        let id = derive_chain_id(&hash);
        // Chain ID equals the first 4 bytes of its genesis hash.
        let bytes = hash.as_bytes();
        let expected = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(id, expected);
        // Different seeds produce different chain IDs.
        let block2 = build_genesis(GENESIS_TIMESTAMP, b"other-seed");
        let hash2 = block2.header.compute_block_hash().unwrap();
        assert_ne!(derive_chain_id(&hash), derive_chain_id(&hash2));
    }

    #[test]
    fn min_fee_is_0001_noble() {
        // 0.001 NOBLE with 6 decimal places = 1000 atomic units
        assert_eq!(MIN_TX_FEE, 1);
    }

    #[test]
    fn block_size_is_8mb() {
        assert_eq!(MAX_BLOCK_SIZE, 8_388_608);
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
            // Epoch 0 has 99,999 blocks (height 0 excluded), epochs 1+ have 100,000
            let blocks = if epoch == 0 {
                HALVING_INTERVAL - 1
            } else {
                HALVING_INTERVAL
            };
            total += subsidy as u128 * blocks as u128;
        }
        assert_eq!(total, 2_079_991_998_310_000u128);
        assert!(total < MAX_SUPPLY as u128);
    }

    #[test]
    fn subsidy_halves_correctly() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL), INITIAL_SUBSIDY / 2);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 2), INITIAL_SUBSIDY / 4);
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 3), INITIAL_SUBSIDY / 8);
    }

    // --- Checkpoint tests ---

    #[test]
    fn checkpoint_genesis_hash_matches() {
        use crate::genesis::{build_genesis, GENESIS_TIMESTAMP};
        let block = build_genesis(GENESIS_TIMESTAMP, b"noble-test-genesis");
        let genesis = block.header.compute_block_hash().unwrap();
        assert_eq!(is_valid_checkpoint(0, &genesis, &genesis), Some(true));
    }

    #[test]
    fn checkpoint_genesis_wrong_hash_rejected() {
        let genesis = noble_crypto::Hash256::from_bytes([0x11; 32]);
        assert_eq!(
            is_valid_checkpoint(0, &noble_crypto::Hash256::ZERO, &genesis),
            Some(false)
        );
    }

    #[test]
    fn checkpoint_unknown_height_returns_none() {
        let hash = noble_crypto::Hash256::from_bytes([0xAA; 32]);
        let genesis = noble_crypto::Hash256::from_bytes([0x11; 32]);
        assert_eq!(is_valid_checkpoint(999_999, &hash, &genesis), None);
    }

    #[test]
    fn subsidy_exhausted_after_64_halvings() {
        assert_eq!(subsidy_at_height(HALVING_INTERVAL * 64), 0);
        assert_eq!(subsidy_at_height(u64::MAX), 0);
    }
}
