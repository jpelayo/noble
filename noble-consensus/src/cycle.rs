// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Deterministic cycle phase tracking. All methods take explicit `now: u64`
//! (no `SystemTime`) for reproducible testing and replay.

use serde::{Deserialize, Serialize};

/// The four phases within each consensus cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CyclePhase {
    /// First quarter: validators propose and broadcast blocks.
    Proposal,
    /// Second quarter: R1 votes cast and collected.
    Voting,
    /// Third quarter: R2 confirmation votes cast and collected.
    Reflection,
    /// Fourth quarter: final block propagation window, commit at boundary.
    Propagation,
}

/// Manages cycle and phase computations using only wall-clock timestamps.
///
/// Cycle numbers are relative to the genesis timestamp so that cycle 0
/// corresponds to the genesis block, cycle 1 to the first post-genesis
/// cycle, and so on.
#[derive(Debug, Clone)]
pub struct CycleManager {
    /// Duration of a full cycle in seconds.
    cycle_duration: u64,
    /// Genesis timestamp — cycles are counted from this origin.
    genesis_timestamp: u64,
}

impl CycleManager {
    /// Create a new cycle manager with the given cycle duration and genesis timestamp.
    ///
    /// `genesis_timestamp` should be the timestamp of the first block in the chain
    /// (read from storage). If no genesis block exists yet, pass `None` — cycles
    /// will not count until `set_genesis_timestamp()` is called.
    pub fn new(cycle_duration_secs: u64, genesis_timestamp: Option<u64>) -> Self {
        assert!(cycle_duration_secs > 0, "cycle duration must be positive");
        Self {
            cycle_duration: cycle_duration_secs,
            genesis_timestamp: genesis_timestamp.unwrap_or(u64::MAX),
        }
    }

    /// Update the genesis timestamp (called when the first block is committed).
    pub fn set_genesis_timestamp(&mut self, ts: u64) {
        self.genesis_timestamp = ts;
    }

    /// Whether a genesis timestamp has been set (i.e., the chain has blocks).
    pub fn has_genesis(&self) -> bool {
        self.genesis_timestamp != u64::MAX
    }

    /// Return the genesis timestamp (only valid when `has_genesis()` is true).
    pub fn genesis_ts(&self) -> u64 {
        self.genesis_timestamp
    }

    /// Return the cycle duration in seconds.
    pub fn cycle_duration(&self) -> u64 {
        self.cycle_duration
    }

    /// Elapsed seconds since genesis (saturating — returns 0 before genesis).
    fn elapsed(&self, now: u64) -> u64 {
        now.saturating_sub(self.genesis_timestamp)
    }

    /// Return the cycle number at the given timestamp (relative to genesis).
    pub fn current_cycle(&self, now: u64) -> u64 {
        self.elapsed(now) / self.cycle_duration
    }

    /// Return the current phase at the given timestamp.
    /// Four quarters: Proposal, Voting, Reflection, Propagation.
    pub fn current_phase(&self, now: u64) -> CyclePhase {
        let offset = self.cycle_offset(now);
        let quarter = self.cycle_duration / 4;
        match offset / quarter {
            0 => CyclePhase::Proposal,
            1 => CyclePhase::Voting,
            2 => CyclePhase::Reflection,
            _ => CyclePhase::Propagation,
        }
    }

    /// Offset within the current cycle (0..cycle_duration).
    pub fn cycle_offset(&self, now: u64) -> u64 {
        self.elapsed(now) % self.cycle_duration
    }

    /// Offset within the current phase (0..cycle_duration/4).
    pub fn phase_offset(&self, now: u64) -> u64 {
        let offset = self.cycle_offset(now);
        let quarter = self.cycle_duration / 4;
        offset % quarter
    }

    /// Seconds until the next phase boundary.
    pub fn seconds_until_phase_change(&self, now: u64) -> u64 {
        let quarter = self.cycle_duration / 4;
        quarter - self.phase_offset(now)
    }

    /// Seconds until the next cycle boundary.
    pub fn seconds_until_cycle_boundary(&self, now: u64) -> u64 {
        self.cycle_duration - self.cycle_offset(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = noble_core::GENESIS_TIMESTAMP;

    fn mgr() -> CycleManager {
        CycleManager::new(960, Some(G))
    }

    #[test]
    fn cycle_zero_at_genesis() {
        assert_eq!(mgr().current_cycle(G), 0);
    }

    #[test]
    fn cycle_zero_before_genesis() {
        assert_eq!(mgr().current_cycle(0), 0);
        assert_eq!(mgr().current_cycle(G - 1), 0);
    }

    #[test]
    fn cycle_increments() {
        let m = mgr();
        assert_eq!(m.current_cycle(G + 959), 0);
        assert_eq!(m.current_cycle(G + 960), 1);
        assert_eq!(m.current_cycle(G + 1919), 1);
        assert_eq!(m.current_cycle(G + 1920), 2);
    }

    #[test]
    fn phase_first_quarter_is_proposal() {
        let m = mgr();
        assert_eq!(m.current_phase(G), CyclePhase::Proposal);
        assert_eq!(m.current_phase(G + 239), CyclePhase::Proposal);
    }

    #[test]
    fn phase_second_quarter_is_voting() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 240), CyclePhase::Voting);
        assert_eq!(m.current_phase(G + 479), CyclePhase::Voting);
    }

    #[test]
    fn phase_third_quarter_is_reflection() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 480), CyclePhase::Reflection);
        assert_eq!(m.current_phase(G + 719), CyclePhase::Reflection);
    }

    #[test]
    fn phase_fourth_quarter_is_propagation() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 720), CyclePhase::Propagation);
        assert_eq!(m.current_phase(G + 959), CyclePhase::Propagation);
    }

    #[test]
    fn phase_transitions_at_quarter_boundaries() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 239), CyclePhase::Proposal);
        assert_eq!(m.current_phase(G + 240), CyclePhase::Voting);
        assert_eq!(m.current_phase(G + 479), CyclePhase::Voting);
        assert_eq!(m.current_phase(G + 480), CyclePhase::Reflection);
        assert_eq!(m.current_phase(G + 719), CyclePhase::Reflection);
        assert_eq!(m.current_phase(G + 720), CyclePhase::Propagation);
    }

    #[test]
    fn seconds_until_phase_change() {
        let m = mgr();
        assert_eq!(m.seconds_until_phase_change(G), 240);
        assert_eq!(m.seconds_until_phase_change(G + 120), 120);
        assert_eq!(m.seconds_until_phase_change(G + 239), 1);
        assert_eq!(m.seconds_until_phase_change(G + 240), 240);
        assert_eq!(m.seconds_until_phase_change(G + 480), 240);
    }

    #[test]
    fn seconds_until_cycle_boundary() {
        let m = mgr();
        assert_eq!(m.seconds_until_cycle_boundary(G), 960);
        assert_eq!(m.seconds_until_cycle_boundary(G + 1), 959);
        assert_eq!(m.seconds_until_cycle_boundary(G + 959), 1);
        assert_eq!(m.seconds_until_cycle_boundary(G + 960), 960);
    }
}

#[cfg(test)]
mod bootstrap_epoch_tests {
    use super::*;

    #[test]
    fn founding_epoch_pins_the_cycle_to_zero() {
        // Genesis witness certificates declare `cycle: 0`, and `verify()`
        // rejects any vote whose cycle differs. That only holds because the
        // founding epoch is represented as `genesis_timestamp = u64::MAX`, so
        // `elapsed = now.saturating_sub(u64::MAX)` saturates to 0.
        //
        // Nothing else documents that dependency. If the founding epoch were
        // represented differently, every genesis certificate would become
        // unverifiable — and the failure would surface at startup and at join,
        // far from the change that caused it.
        let mgr = CycleManager::new(noble_core::CYCLE_DURATION_SECS, Some(u64::MAX));
        for now in [0u64, 1, 1_700_000_000, u64::MAX / 2] {
            assert_eq!(
                mgr.current_cycle(now),
                0,
                "the founding epoch must compute cycle 0 at any wall clock (now={now})"
            );
        }
    }
}
