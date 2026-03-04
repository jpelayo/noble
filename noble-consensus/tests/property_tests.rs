// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Property-based tests for the consensus FSM using proptest.

use noble_consensus::config::ConsensusConfig;
use noble_consensus::cycle::CyclePhase;
use noble_consensus::validator::ValidatorList;
use noble_consensus::vote::{PorVote, VoteManager};
use noble_consensus::{ConsensusStateMachine, CycleEngine, CycleEvent};
use noble_crypto::{ed25519, Hash256, NoblePrivateKey};
use proptest::prelude::*;

/// Generate a random validator keypair.
fn arb_validator() -> (NoblePrivateKey, noble_crypto::NoblePublicKey) {
    let (sk, _) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk);
    let pub_key = priv_key.public_key();
    (priv_key, pub_key)
}

// ─── Property 1: Valid phase transitions ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// After any number of tick events, the engine's phase is always
    /// either Validation (0) or Reflection (1).
    #[test]
    fn phase_is_always_valid(
        timestamps in proptest::collection::vec(0u64..100_000, 1..20),
    ) {
        let (_vp, vpub) = arb_validator();
        let mut val_list = ValidatorList::new();
        val_list.add_validator(vpub, 100, 0);
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            val_list,
            0,
            Hash256::ZERO,
            noble_core::MAINNET_CHAIN_ID,
            None,
            Some(0),
        );

        for ts in timestamps {
            engine.step(CycleEvent::Tick { now: ts });
            let phase = engine.current_phase();
            prop_assert!(
                matches!(phase, CyclePhase::Validation | CyclePhase::Reflection),
                "phase must be Validation or Reflection, got {:?}",
                phase
            );
        }
    }
}

// ─── Property 2: Majority requires >50% votes ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// With fewer than ceil(n/2)+1 votes for any candidate, compute_majority
    /// never produces a Strong adopt result.
    #[test]
    fn no_strong_majority_without_50_pct(
        n_validators in 3usize..20,
        n_votes in 1usize..10,
    ) {
        let config = ConsensusConfig::default();
        let mut mgr = VoteManager::new();
        mgr.set_current_cycle(1);

        // Ensure votes < majority threshold
        let actual_votes = n_votes.min(n_validators / 2); // strictly < 50%

        let candidate = Hash256::from_bytes([0xAB; 32]);

        for i in 0..actual_votes {
            let (priv_key, pub_key) = arb_validator();
            let vote = PorVote::sign(1, candidate, &priv_key, pub_key).unwrap();
            let peer_id = format!("peer{}", i).into_bytes();
            let _ = mgr.record_vote(&peer_id, &vote);
        }

        let result = mgr.compute_majority(n_validators, &config);
        match result {
            noble_consensus::vote::MigrationResult::Adopt { strength, .. } => {
                // If adopted, must be Plurality (not Strong)
                prop_assert!(
                    !matches!(strength, noble_consensus::vote::ConsensusStrength::Strong),
                    "strong majority should require >50% votes, got {:?} with {}/{} votes",
                    strength, actual_votes, n_validators
                );
            }
            noble_consensus::vote::MigrationResult::Indeterminate => {
                // Fine — no majority
            }
        }
    }
}

// ─── Property 3: No candidate without votes ──────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// When VoteManager has zero votes, compute_majority is always Indeterminate.
    #[test]
    fn no_candidate_without_votes(
        n_validators in 1usize..50,
    ) {
        let config = ConsensusConfig::default();
        let mgr = VoteManager::new();

        let result = mgr.compute_majority(n_validators, &config);
        prop_assert!(
            matches!(result, noble_consensus::vote::MigrationResult::Indeterminate),
            "zero votes should always be Indeterminate, got {:?}",
            result
        );
    }
}

// ─── Property 4: Monotonic phase timing ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// phase_timing() returns phase_index in [0, 1], and the remaining
    /// seconds never exceed the cycle duration.
    #[test]
    fn monotonic_phase_timing(
        tick_time in 0u64..50_000,
    ) {
        let (_vp, vpub) = arb_validator();
        let mut val_list = ValidatorList::new();
        val_list.add_validator(vpub, 100, 0);
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            val_list,
            0,
            Hash256::ZERO,
            noble_core::MAINNET_CHAIN_ID,
            None,
            Some(0),
        );

        engine.step(CycleEvent::Tick { now: tick_time });
        let (phase_idx, phase_remaining, cycle_remaining) = engine.phase_timing();

        prop_assert!(phase_idx <= 1, "phase_index must be 0 or 1, got {}", phase_idx);
        prop_assert!(
            phase_remaining <= noble_core::CYCLE_DURATION_SECS,
            "phase_remaining {} exceeds cycle duration {}",
            phase_remaining,
            noble_core::CYCLE_DURATION_SECS
        );
        prop_assert!(
            cycle_remaining <= noble_core::CYCLE_DURATION_SECS,
            "cycle_remaining {} exceeds cycle duration {}",
            cycle_remaining,
            noble_core::CYCLE_DURATION_SECS
        );
    }
}

// ─── Property 5: Non-validator vote rejected ─────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Votes from keys not in the validator list are rejected with a ban action.
    #[test]
    fn non_validator_vote_always_rejected(
        cycle in 0u64..100,
    ) {
        let (_known_priv, known_pub) = arb_validator();
        let (unknown_priv, unknown_pub) = arb_validator();

        let mut val_list = ValidatorList::new();
        val_list.add_validator(known_pub, 100, 0);
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            val_list,
            0,
            Hash256::ZERO,
            noble_core::MAINNET_CHAIN_ID,
            None,
            Some(0),
        );
        engine.step(CycleEvent::Tick { now: cycle * 1800 });

        // Force Reflection phase for vote acceptance
        engine.step(CycleEvent::PhaseTransition {
            cycle,
            new_phase: CyclePhase::Reflection,
        });

        let candidate = Hash256::from_bytes([0xCC; 32]);
        let vote = PorVote::sign(cycle, candidate, &unknown_priv, unknown_pub).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"unknown_peer".to_vec(),
        });

        // Should have a ban action
        let has_ban = outputs.iter().any(|o| {
            matches!(o, noble_consensus::CycleIo::BanPeer { .. })
        });
        prop_assert!(
            has_ban,
            "non-validator vote must always produce a BanPeer action"
        );
    }
}
