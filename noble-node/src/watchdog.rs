// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Liveness watchdog for the node and network event loops.
//!
//! On 2026-08-17 both event loops froze for as long as a dying TCP connection
//! took to be killed by the kernel: 18–53 minutes on macOS (retransmission
//! timeout), **11.5 hours** on Linux (idle-direction socket, which never times
//! out — the node was a zombie until an operator restarted it). During a
//! freeze nothing runs: no cycles, no proposals, no pings, no logs. The
//! "Layer 3" dead-peer reaper could not help because it runs inside the loop
//! that freezes.
//!
//! The watchdog enforces the liveness invariant structurally instead of by
//! luck: each loop stamps a heartbeat every iteration; an independent task —
//! owning nothing but the atomics — checks the stamps. A stall is first
//! reported (naming the loop and the select arm it froze in, so the next
//! incident identifies its own cause), and if it persists past the hard limit
//! the process aborts. `brew services` runs the node with `keep_alive true`,
//! so an abort is a bounded ~seconds restart instead of an unbounded zombie.
//!
//! This module makes NO consensus decisions. It observes wall-clock liveness
//! of the loops and nothing else.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Stall age (seconds) after which the watchdog starts reporting the freeze.
pub const WATCHDOG_SOFT_SECS: u64 = 120;

/// Stall age (seconds) after which the process aborts so the service manager
/// restarts it. Far above any legitimate pause, far below the 11.5 h observed.
pub const WATCHDOG_HARD_SECS: u64 = 600;

/// How often the watchdog task samples the heartbeats.
pub const WATCHDOG_CHECK_SECS: u64 = 30;

/// Which select arm a loop was last processing. Stored as `u32` in an atomic
/// beside the heartbeat so a frozen loop's last known position survives to be
/// reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoopArm {
    /// Loop iteration begun, no arm entered yet.
    Idle = 0,
    /// Node loop: processing a `NetworkEvent`.
    NetworkEvent = 1,
    /// Node loop: consensus cycle tick.
    CycleTick = 2,
    /// Node loop: periodic / delayed NodeAnnounce publication.
    AnnounceTimer = 3,
    /// Node loop: another timer arm (redial, faucet, metrics, …).
    OtherTimer = 4,
    /// Network loop: handling a swarm event.
    SwarmEvent = 5,
    /// Network loop: handling a `NetworkCommand`.
    Command = 6,
}

impl LoopArm {
    /// Human-readable arm name for the stall report.
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::NetworkEvent => "network_event",
            Self::CycleTick => "cycle_tick",
            Self::AnnounceTimer => "announce_timer",
            Self::OtherTimer => "other_timer",
            Self::SwarmEvent => "swarm_event",
            Self::Command => "command",
        }
    }

    /// Decode from the atomic's raw value.
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::NetworkEvent,
            2 => Self::CycleTick,
            3 => Self::AnnounceTimer,
            4 => Self::OtherTimer,
            5 => Self::SwarmEvent,
            6 => Self::Command,
            _ => Self::Idle,
        }
    }
}

/// One loop's published liveness state: heartbeat + last arm entered.
#[derive(Clone)]
pub struct Heartbeat {
    beat: Arc<AtomicU64>,
    arm: Arc<AtomicU32>,
}

impl Heartbeat {
    pub fn new() -> Self {
        Self {
            beat: Arc::new(AtomicU64::new(now_unix())),
            arm: Arc::new(AtomicU32::new(LoopArm::Idle as u32)),
        }
    }

    /// Wrap heartbeat atomics owned elsewhere (the network service loop
    /// exports its pair on `NetworkHandle`; arm codes are documented there and
    /// decoded by [`LoopArm::from_u32`]).
    pub fn from_parts(beat: Arc<AtomicU64>, arm: Arc<AtomicU32>) -> Self {
        Self { beat, arm }
    }

    /// Stamp the heartbeat. Called at the top of every loop iteration.
    pub fn tick(&self) {
        self.beat.store(now_unix(), Ordering::Relaxed);
    }

    /// Record which arm the loop is about to process.
    pub fn enter(&self, arm: LoopArm) {
        self.arm.store(arm as u32, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.beat.load(Ordering::Relaxed))
    }

    fn beat_value(&self) -> u64 {
        self.beat.load(Ordering::Relaxed)
    }

    fn last_arm(&self) -> LoopArm {
        LoopArm::from_u32(self.arm.load(Ordering::Relaxed))
    }
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new()
    }
}

/// The watchdog's judgement of one heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Beat is fresh.
    Ok,
    /// Stalled past the soft limit: report loudly, keep watching.
    Soft { stalled_secs: u64 },
    /// Stalled past the hard limit: abort so the service manager restarts us.
    Hard { stalled_secs: u64 },
}

/// Pure decision rule — the whole policy in one testable place.
///
/// (House pattern: `advertised_suppression_expired`, `clock_drift_pause` —
/// rules that decide whether the node lives or stalls are pure functions.)
pub fn watchdog_verdict(now: u64, beat: u64, soft_secs: u64, hard_secs: u64) -> Verdict {
    let stalled_secs = now.saturating_sub(beat);
    if stalled_secs > hard_secs {
        Verdict::Hard { stalled_secs }
    } else if stalled_secs > soft_secs {
        Verdict::Soft { stalled_secs }
    } else {
        Verdict::Ok
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Spawn the watchdog over the given (name, heartbeat) pairs.
///
/// The task owns only the atomics: a frozen loop cannot freeze its observer.
/// Suspend/resume safety: the watchdog sleeps too; on wake, loops re-stamp
/// before its next 30 s sample, so system sleep does not false-trip the abort.
pub fn spawn(
    watched: Vec<(&'static str, Heartbeat)>,
    activity_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(WATCHDOG_CHECK_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = now_unix();
            for (name, hb) in &watched {
                match watchdog_verdict(
                    now,
                    hb.beat_value(),
                    WATCHDOG_SOFT_SECS,
                    WATCHDOG_HARD_SECS,
                ) {
                    Verdict::Ok => {}
                    Verdict::Soft { stalled_secs } => {
                        let arm = hb.last_arm().label();
                        tracing::error!(
                            task = "watchdog",
                            loop_name = name,
                            stalled_secs,
                            last_arm = arm,
                            "event loop stalled — no heartbeat for {stalled_secs}s \
                             (frozen in arm '{arm}')"
                        );
                        if let Err(e) = activity_tx.send(serde_json::json!({
                            "event": "loop_stalled",
                            "loop": name,
                            "stalled_secs": stalled_secs,
                            "last_arm": arm,
                        })) {
                            tracing::debug!(
                                task = "watchdog",
                                "loop_stalled event dropped (no subscribers): {e}"
                            );
                        }
                    }
                    Verdict::Hard { stalled_secs } => {
                        let arm = hb.last_arm().label();
                        tracing::error!(
                            task = "watchdog",
                            loop_name = name,
                            stalled_secs,
                            last_arm = arm,
                            "CRITICAL: event loop dead for {stalled_secs}s (frozen in arm \
                             '{arm}') — aborting so the service manager restarts the node. \
                             A bounded restart beats an unbounded zombie: on 2026-08-17 a \
                             node in this state was silent for 11.5 hours."
                        );
                        // Give the log line a moment to flush, then die.
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        std::process::abort();
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_beat_is_ok() {
        assert_eq!(
            watchdog_verdict(1_000, 1_000, WATCHDOG_SOFT_SECS, WATCHDOG_HARD_SECS),
            Verdict::Ok
        );
        assert_eq!(
            watchdog_verdict(1_120, 1_000, WATCHDOG_SOFT_SECS, WATCHDOG_HARD_SECS),
            Verdict::Ok,
            "exactly at the soft limit is not over it"
        );
    }

    #[test]
    fn soft_stall_reports_and_hard_stall_aborts() {
        assert_eq!(
            watchdog_verdict(1_121, 1_000, WATCHDOG_SOFT_SECS, WATCHDOG_HARD_SECS),
            Verdict::Soft { stalled_secs: 121 }
        );
        assert_eq!(
            watchdog_verdict(1_601, 1_000, WATCHDOG_SOFT_SECS, WATCHDOG_HARD_SECS),
            Verdict::Hard { stalled_secs: 601 }
        );
    }

    #[test]
    fn beat_in_the_future_never_trips() {
        // Clock stepped backwards between stamp and check — saturating math
        // must read as "fresh", not as a giant stall.
        assert_eq!(
            watchdog_verdict(900, 1_000, WATCHDOG_SOFT_SECS, WATCHDOG_HARD_SECS),
            Verdict::Ok
        );
    }

    #[test]
    fn every_arm_has_a_distinct_label_and_roundtrips() {
        let arms = [
            LoopArm::Idle,
            LoopArm::NetworkEvent,
            LoopArm::CycleTick,
            LoopArm::AnnounceTimer,
            LoopArm::OtherTimer,
            LoopArm::SwarmEvent,
            LoopArm::Command,
        ];
        let mut seen = std::collections::HashSet::new();
        for arm in arms {
            assert!(seen.insert(arm.label()), "duplicate label {}", arm.label());
            assert_eq!(LoopArm::from_u32(arm as u32), arm);
        }
        assert_eq!(LoopArm::from_u32(999), LoopArm::Idle, "unknown decodes to Idle");
    }

    #[test]
    fn heartbeat_tick_refreshes_age() {
        let hb = Heartbeat::new();
        hb.enter(LoopArm::CycleTick);
        hb.tick();
        let now = now_unix();
        assert!(hb.age_secs(now) <= 1);
        assert_eq!(hb.last_arm(), LoopArm::CycleTick);
    }
}
