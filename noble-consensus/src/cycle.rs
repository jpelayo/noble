// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Deterministic cycle phase tracking. All methods take explicit `now: u64`
//! (no `SystemTime`) for reproducible testing and replay.

use serde::{Deserialize, Serialize};

/// The two alternating phases within each consensus cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CyclePhase {
    /// First half of the cycle: validators propose and broadcast blocks.
    Validation,
    /// Second half: validators vote on candidates and reach consensus.
    Reflection,
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
    /// Create a new cycle manager with the given cycle duration.
    pub fn new(cycle_duration_secs: u64) -> Self {
        assert!(cycle_duration_secs > 0, "cycle duration must be positive");
        Self {
            cycle_duration: cycle_duration_secs,
            genesis_timestamp: noble_core::GENESIS_TIMESTAMP,
        }
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
    /// First half (offset < duration/2) = Validation, second half = Reflection.
    pub fn current_phase(&self, now: u64) -> CyclePhase {
        let offset = self.cycle_offset(now);
        if offset < self.cycle_duration / 2 {
            CyclePhase::Validation
        } else {
            CyclePhase::Reflection
        }
    }

    /// Offset within the current cycle (0..cycle_duration).
    pub fn cycle_offset(&self, now: u64) -> u64 {
        self.elapsed(now) % self.cycle_duration
    }

    /// Offset within the current phase (0..cycle_duration/2).
    pub fn phase_offset(&self, now: u64) -> u64 {
        let offset = self.cycle_offset(now);
        let half = self.cycle_duration / 2;
        offset % half
    }

    /// Seconds until the next phase boundary.
    pub fn seconds_until_phase_change(&self, now: u64) -> u64 {
        let half = self.cycle_duration / 2;
        half - self.phase_offset(now)
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
        CycleManager::new(1800)
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
        assert_eq!(m.current_cycle(G + 1799), 0);
        assert_eq!(m.current_cycle(G + 1800), 1);
        assert_eq!(m.current_cycle(G + 3599), 1);
        assert_eq!(m.current_cycle(G + 3600), 2);
    }

    #[test]
    fn phase_first_half_is_validation() {
        let m = mgr();
        assert_eq!(m.current_phase(G), CyclePhase::Validation);
        assert_eq!(m.current_phase(G + 899), CyclePhase::Validation);
    }

    #[test]
    fn phase_second_half_is_reflection() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 900), CyclePhase::Reflection);
        assert_eq!(m.current_phase(G + 1799), CyclePhase::Reflection);
    }

    #[test]
    fn phase_transition_at_midpoint() {
        let m = mgr();
        assert_eq!(m.current_phase(G + 899), CyclePhase::Validation);
        assert_eq!(m.current_phase(G + 900), CyclePhase::Reflection);
    }

    #[test]
    fn seconds_until_phase_change() {
        let m = mgr();
        assert_eq!(m.seconds_until_phase_change(G), 900);
        assert_eq!(m.seconds_until_phase_change(G + 450), 450);
        assert_eq!(m.seconds_until_phase_change(G + 899), 1);
        assert_eq!(m.seconds_until_phase_change(G + 900), 900);
    }

    #[test]
    fn seconds_until_cycle_boundary() {
        let m = mgr();
        assert_eq!(m.seconds_until_cycle_boundary(G), 1800);
        assert_eq!(m.seconds_until_cycle_boundary(G + 1), 1799);
        assert_eq!(m.seconds_until_cycle_boundary(G + 1799), 1);
        assert_eq!(m.seconds_until_cycle_boundary(G + 1800), 1800);
    }
}
