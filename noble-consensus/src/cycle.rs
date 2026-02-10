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
#[derive(Debug, Clone)]
pub struct CycleManager {
    /// Duration of a full cycle in seconds.
    cycle_duration: u64,
}

impl CycleManager {
    /// Create a new cycle manager with the given cycle duration.
    pub fn new(cycle_duration_secs: u64) -> Self {
        assert!(cycle_duration_secs > 0, "cycle duration must be positive");
        Self {
            cycle_duration: cycle_duration_secs,
        }
    }

    /// Return the cycle number at the given timestamp.
    pub fn current_cycle(&self, now: u64) -> u64 {
        now / self.cycle_duration
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
        now % self.cycle_duration
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

    fn mgr() -> CycleManager {
        CycleManager::new(1800)
    }

    #[test]
    fn cycle_zero_at_genesis() {
        assert_eq!(mgr().current_cycle(0), 0);
    }

    #[test]
    fn cycle_increments() {
        let m = mgr();
        assert_eq!(m.current_cycle(1799), 0);
        assert_eq!(m.current_cycle(1800), 1);
        assert_eq!(m.current_cycle(3599), 1);
        assert_eq!(m.current_cycle(3600), 2);
    }

    #[test]
    fn phase_first_half_is_validation() {
        let m = mgr();
        assert_eq!(m.current_phase(0), CyclePhase::Validation);
        assert_eq!(m.current_phase(899), CyclePhase::Validation);
    }

    #[test]
    fn phase_second_half_is_reflection() {
        let m = mgr();
        assert_eq!(m.current_phase(900), CyclePhase::Reflection);
        assert_eq!(m.current_phase(1799), CyclePhase::Reflection);
    }

    #[test]
    fn phase_transition_at_midpoint() {
        let m = mgr();
        // Just before midpoint → Validation
        assert_eq!(m.current_phase(899), CyclePhase::Validation);
        // Exactly at midpoint → Reflection
        assert_eq!(m.current_phase(900), CyclePhase::Reflection);
    }

    #[test]
    fn seconds_until_phase_change() {
        let m = mgr();
        assert_eq!(m.seconds_until_phase_change(0), 900);
        assert_eq!(m.seconds_until_phase_change(450), 450);
        assert_eq!(m.seconds_until_phase_change(899), 1);
        // At phase boundary, full half remains
        assert_eq!(m.seconds_until_phase_change(900), 900);
    }

    #[test]
    fn seconds_until_cycle_boundary() {
        let m = mgr();
        assert_eq!(m.seconds_until_cycle_boundary(0), 1800);
        assert_eq!(m.seconds_until_cycle_boundary(1), 1799);
        assert_eq!(m.seconds_until_cycle_boundary(1799), 1);
        assert_eq!(m.seconds_until_cycle_boundary(1800), 1800);
    }
}
