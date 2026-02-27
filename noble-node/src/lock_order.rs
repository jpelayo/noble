// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Lock ordering discipline for shared state.
//!
//! All locks in the NOBLE node follow a strict total order to prevent deadlocks.
//! When acquiring multiple locks in the same code path, **always** acquire them
//! in ascending order according to the [`LockOrder`] enum discriminant.
//!
//! # Lock Hierarchy (lowest → highest)
//!
//! ```text
//!   WalletKeystore (0)
//!     ↓
//!   WalletState (1)
//!     ↓
//!   Storage (2)
//!     ↓
//!   Consensus (3)
//!     ↓
//!   Mempool (4)
//!     ↓
//!   NetworkStats (5)
//!     ↓
//!   PeerInfo (6)
//!     ↓
//!   TotpValidator (7)
//!     ↓
//!   MaxNetworkVersion (8)
//!     ↓
//!   TlsCertInfo (9)
//! ```
//!
//! # Rules
//!
//! 1. **Never acquire a lower-numbered lock while holding a higher-numbered one.**
//!    For example, never acquire `Storage` (2) while holding `Mempool` (4).
//!
//! 2. **Prefer drop-before-acquire**: When possible, drop a lock guard before
//!    acquiring the next one. This shrinks the critical section and avoids
//!    holding multiple locks simultaneously.
//!
//! 3. **Do not perform I/O under a lock**: File writes, network calls, or other
//!    blocking I/O should happen outside lock scopes. Copy out the data you need,
//!    drop the guard, then perform I/O.
//!
//! 4. **Read locks still follow ordering**: Even `RwLock::read()` must respect
//!    the hierarchy. A writer waiting for readers can block indefinitely if
//!    ordering is violated.
//!
//! # Known Multi-Lock Sites
//!
//! | Location | Locks held | Notes |
//! |----------|-----------|-------|
//! | `wallet.rs` `get_wallet_info` | keystore → wallet_state → storage → mempool | 4 concurrent guards |
//! | `wallet.rs` `send_transfer` | wallet_state → keystore → storage → mempool | keystore released before storage |
//! | `transaction.rs` `submit_transaction` | storage → mempool | storage held during admit() |
//! | `node.rs` `process_cycle_actions` (CommitBlock) | storage → consensus → mempool | sequential scoping |
//! | `node.rs` (PeerConnected) | network_stats → consensus → peer_info | sequential scoping |

/// Defines the canonical acquisition order for all shared locks.
///
/// Lower discriminant values **must** be acquired before higher values.
/// This enum is not used at runtime in release builds — it serves as
/// documentation and powers the debug-mode acquisition tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[allow(dead_code)]
pub enum LockOrder {
    /// `Arc<Mutex<KeyStore>>` — wallet encryption / signing keys.
    WalletKeystore = 0,
    /// `Arc<Mutex<WalletState>>` — lock/unlock state with auto-expire.
    WalletState = 1,
    /// `Arc<RwLock<S>>` — block and transaction persistence.
    Storage = 2,
    /// `Arc<RwLock<CycleEngine>>` — PoR consensus FSM.
    Consensus = 3,
    /// `Arc<Mutex<Mempool>>` — pending transaction pool.
    Mempool = 4,
    /// `Arc<RwLock<NetworkStats>>` — peer count aggregates.
    NetworkStats = 5,
    /// `Arc<RwLock<HashMap<String, PeerInfoEntry>>>` — live peer metadata.
    PeerInfo = 6,
    /// `Arc<RwLock<TotpValidator>>` — TOTP authentication state.
    TotpValidator = 7,
    /// `Arc<RwLock<String>>` — highest observed peer software version.
    MaxNetworkVersion = 8,
    /// `RwLock<Option<String>>` in `ApiState` — TLS certificate metadata (fingerprint, expiry, SANs).
    TlsCertInfo = 9,
}

impl std::fmt::Display for LockOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}({})", *self as u8)
    }
}

// ---------------------------------------------------------------------------
// Debug-mode lock acquisition tracker
// ---------------------------------------------------------------------------

#[cfg(debug_assertions)]
mod tracker {
    use super::LockOrder;
    use std::cell::RefCell;

    thread_local! {
        /// Stack of currently held locks on this thread (in acquisition order).
        static HELD: RefCell<Vec<LockOrder>> = const { RefCell::new(Vec::new()) };
    }

    /// Record that we are about to acquire `lock`.
    ///
    /// # Panics
    ///
    /// Panics if `lock` would violate the ordering discipline (i.e. a
    /// higher-or-equal-ordered lock is already held on this thread).
    pub fn acquire(lock: LockOrder) {
        HELD.with(|held| {
            let held = held.borrow();
            if let Some(&top) = held.last() {
                assert!(
                    lock > top,
                    "LOCK ORDER VIOLATION: attempting to acquire {lock} while holding {top}. \
                     Locks must be acquired in ascending LockOrder.",
                );
            }
        });
        HELD.with(|held| held.borrow_mut().push(lock));
    }

    /// Record that `lock` has been released.
    pub fn release(lock: LockOrder) {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(pos) = held.iter().rposition(|&l| l == lock) {
                held.remove(pos);
            }
        });
    }

    /// Returns a snapshot of currently held locks on this thread.
    pub fn held_locks() -> Vec<LockOrder> {
        HELD.with(|held| held.borrow().clone())
    }
}

// Re-export tracker functions. In debug builds these perform real validation;
// in release builds they compile to no-ops. Currently used by tests; will be
// wired into lock wrappers when instrumentation is added.

#[cfg(debug_assertions)]
pub use tracker::{acquire, held_locks, release};

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn acquire(_lock: LockOrder) {}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn release(_lock: LockOrder) {}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn held_locks() -> Vec<LockOrder> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_order_discriminants_are_sequential() {
        let orders = [
            LockOrder::WalletKeystore,
            LockOrder::WalletState,
            LockOrder::Storage,
            LockOrder::Consensus,
            LockOrder::Mempool,
            LockOrder::NetworkStats,
            LockOrder::PeerInfo,
            LockOrder::TotpValidator,
            LockOrder::MaxNetworkVersion,
            LockOrder::TlsCertInfo,
        ];
        for pair in orders.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} should be less than {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn valid_ordering_does_not_panic() {
        acquire(LockOrder::Storage);
        acquire(LockOrder::Consensus);
        acquire(LockOrder::Mempool);
        release(LockOrder::Mempool);
        release(LockOrder::Consensus);
        release(LockOrder::Storage);
    }

    #[test]
    #[should_panic(expected = "LOCK ORDER VIOLATION")]
    fn invalid_ordering_panics_in_debug() {
        acquire(LockOrder::Mempool);
        // Acquiring Storage (2) while holding Mempool (4) is a violation.
        acquire(LockOrder::Storage);
    }
}
