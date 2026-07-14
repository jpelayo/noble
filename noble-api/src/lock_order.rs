// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Lock ordering discipline for shared state — **enforced at runtime in debug builds**.
//!
//! All locks in the NOBLE node follow a strict total order to prevent deadlocks.
//! When acquiring multiple locks in the same code path, **always** acquire them
//! in ascending order according to the [`LockOrder`] enum discriminant.
//!
//! Unlike a pure documentation aid, this module is *wired into the live locks*
//! via [`TrackedRwLock`] / [`TrackedMutex`]. Every `.read()`/`.write()`/`.lock()`
//! on a shared lock records the acquisition on a thread-local stack and, in
//! debug/CI builds, **panics on any ordering violation** (including a recursive
//! same-rank re-acquire — the parking_lot writer-fairness footgun that wedged
//! the production node in 0.138.0). In release builds the tracker compiles to
//! a no-op, so there is zero runtime cost and no possibility of a production
//! panic — the ordering is guaranteed structurally by the code, and the tracker
//! merely proves it in CI.
//!
//! # Lock Hierarchy (lowest → highest)
//!
//! ```text
//!   WalletKeystore (0) → WalletState (1) → Storage (2) → ValidatorRegistry (3)
//!   → Consensus (4) → Mempool (5) → NetworkStats (6) → PeerInfo (7)
//!   → TotpValidator (8) → MaxNetworkVersion (9) → TlsCertInfo (10)
//!   → NodeIdentity (11) → ValidatorPubkey (12)
//! ```
//!
//! # Rules
//!
//! 1. **Never acquire a lower-or-equal-numbered lock while holding another.**
//!    A recursive `read()` on the same lock is a violation too: parking_lot is
//!    writer-fair, so a second reader queued behind a waiting writer deadlocks
//!    against the reader already held on this thread.
//! 2. **Prefer drop-before-acquire**: snapshot the data you need under one guard,
//!    drop it, then take the next lock. Shrinks the critical section to nothing
//!    held-across-acquire.
//! 3. **Do not perform I/O or call `resolve_*_name` under a lock**: those helpers
//!    acquire storage(2)+registry(3)+identity(11)+pubkey(12) themselves.

/// Defines the canonical acquisition order for all shared locks.
///
/// Lower discriminant values **must** be acquired before higher values, and a
/// value already held may **not** be re-acquired (recursive locks are banned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LockOrder {
    /// `Arc<Mutex<KeyStore>>` — wallet encryption / signing keys.
    WalletKeystore = 0,
    /// `Arc<Mutex<WalletState>>` — lock/unlock state with auto-expire.
    WalletState = 1,
    /// `Arc<RwLock<S>>` — block and transaction persistence.
    Storage = 2,
    /// `Arc<RwLock<ValidatorRegistry>>` — validator/participant metadata.
    ValidatorRegistry = 3,
    /// `Arc<RwLock<CycleEngine>>` — PoR consensus FSM.
    Consensus = 4,
    /// `Arc<Mutex<Mempool>>` — pending transaction pool.
    Mempool = 5,
    /// `Arc<RwLock<NetworkStats>>` — peer count aggregates.
    NetworkStats = 6,
    /// `Arc<RwLock<HashMap<String, PeerInfoEntry>>>` — live peer metadata.
    PeerInfo = 7,
    /// `Arc<RwLock<TotpValidator>>` — TOTP authentication state.
    TotpValidator = 8,
    /// `Arc<RwLock<String>>` — highest observed peer software version.
    MaxNetworkVersion = 9,
    /// `RwLock<Option<String>>` in `ApiState` — TLS certificate metadata.
    TlsCertInfo = 10,
    /// `Arc<RwLock<NodeIdentityData>>` — node identity (name, host, country).
    /// Always acquired after storage/registry; placed near the top so every
    /// existing concurrent hold stays ascending.
    NodeIdentity = 11,
    /// `RwLock<Option<String>>` in `ApiState` — this node's validator pubkey hex.
    ValidatorPubkey = 12,
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
    /// Panics if `lock` would violate the ordering discipline — i.e. a
    /// higher-**or-equal**-ordered lock is already held on this thread. The
    /// equal case catches recursive same-lock re-acquisition, which deadlocks
    /// under parking_lot writer-fairness.
    pub fn acquire(lock: LockOrder) {
        HELD.with(|held| {
            if let Some(&top) = held.borrow().last() {
                assert!(
                    lock > top,
                    "LOCK ORDER VIOLATION: attempting to acquire {lock} while holding {top}. \
                     Locks must be acquired in strictly ascending LockOrder (no recursive/equal \
                     re-acquire). Snapshot-and-drop the held guard before taking the next lock.",
                );
            }
            held.borrow_mut().push(lock);
        });
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
    #[allow(dead_code)]
    pub fn held_locks() -> Vec<LockOrder> {
        HELD.with(|held| held.borrow().clone())
    }
}

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
#[allow(dead_code)]
pub fn held_locks() -> Vec<LockOrder> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tracked lock wrappers — the live enforcement hook
// ---------------------------------------------------------------------------

use std::ops::{Deref, DerefMut};

/// A `parking_lot::RwLock<T>` tagged with its [`LockOrder`] rank. Every
/// `read()`/`write()` records the acquisition (and, in debug builds, panics on
/// an ordering violation); the returned guard releases the record on `Drop`.
///
/// The guards `Deref`/`DerefMut` to `T`, so existing `.read().field` /
/// `.write().mutate()` call sites compile unchanged.
pub struct TrackedRwLock<T: ?Sized> {
    order: LockOrder,
    inner: parking_lot::RwLock<T>,
}

impl<T> TrackedRwLock<T> {
    /// Wrap `value` at the given lock-order `rank`.
    pub fn new(rank: LockOrder, value: T) -> Self {
        Self { order: rank, inner: parking_lot::RwLock::new(value) }
    }

    /// Consume the lock, returning the inner value. No acquisition is recorded
    /// (the lock is being destroyed, so no guard can outlive it).
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> TrackedRwLock<T> {
    /// Acquire a shared read guard, recording the ordered acquisition.
    pub fn read(&self) -> TrackedReadGuard<'_, T> {
        acquire(self.order);
        TrackedReadGuard { order: self.order, guard: self.inner.read() }
    }

    /// Acquire an exclusive write guard, recording the ordered acquisition.
    pub fn write(&self) -> TrackedWriteGuard<'_, T> {
        acquire(self.order);
        TrackedWriteGuard { order: self.order, guard: self.inner.write() }
    }

    /// The lock-order rank this lock was tagged with.
    #[allow(dead_code)]
    pub fn order(&self) -> LockOrder {
        self.order
    }
}

/// RAII read guard for [`TrackedRwLock`]; releases the order record on drop.
pub struct TrackedReadGuard<'a, T: ?Sized> {
    order: LockOrder,
    guard: parking_lot::RwLockReadGuard<'a, T>,
}

impl<T: ?Sized> Deref for TrackedReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> Drop for TrackedReadGuard<'_, T> {
    fn drop(&mut self) {
        release(self.order);
    }
}

/// RAII write guard for [`TrackedRwLock`]; releases the order record on drop.
pub struct TrackedWriteGuard<'a, T: ?Sized> {
    order: LockOrder,
    guard: parking_lot::RwLockWriteGuard<'a, T>,
}

impl<T: ?Sized> Deref for TrackedWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> DerefMut for TrackedWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T: ?Sized> Drop for TrackedWriteGuard<'_, T> {
    fn drop(&mut self) {
        release(self.order);
    }
}

/// A `parking_lot::Mutex<T>` tagged with its [`LockOrder`] rank.
pub struct TrackedMutex<T: ?Sized> {
    order: LockOrder,
    inner: parking_lot::Mutex<T>,
}

impl<T> TrackedMutex<T> {
    /// Wrap `value` at the given lock-order `rank`.
    pub fn new(rank: LockOrder, value: T) -> Self {
        Self { order: rank, inner: parking_lot::Mutex::new(value) }
    }

    /// Consume the lock, returning the inner value.
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> TrackedMutex<T> {
    /// Acquire the mutex, recording the ordered acquisition.
    pub fn lock(&self) -> TrackedMutexGuard<'_, T> {
        acquire(self.order);
        TrackedMutexGuard { order: self.order, guard: self.inner.lock() }
    }

    /// The lock-order rank this lock was tagged with.
    #[allow(dead_code)]
    pub fn order(&self) -> LockOrder {
        self.order
    }
}

/// RAII guard for [`TrackedMutex`]; releases the order record on drop.
pub struct TrackedMutexGuard<'a, T: ?Sized> {
    order: LockOrder,
    guard: parking_lot::MutexGuard<'a, T>,
}

impl<T: ?Sized> Deref for TrackedMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> DerefMut for TrackedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T: ?Sized> Drop for TrackedMutexGuard<'_, T> {
    fn drop(&mut self) {
        release(self.order);
    }
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
            LockOrder::ValidatorRegistry,
            LockOrder::Consensus,
            LockOrder::Mempool,
            LockOrder::NetworkStats,
            LockOrder::PeerInfo,
            LockOrder::TotpValidator,
            LockOrder::MaxNetworkVersion,
            LockOrder::TlsCertInfo,
            LockOrder::NodeIdentity,
            LockOrder::ValidatorPubkey,
        ];
        for pair in orders.windows(2) {
            assert!(pair[0] < pair[1], "{:?} !< {:?}", pair[0], pair[1]);
        }
    }

    #[test]
    fn valid_ascending_ordering_does_not_panic() {
        let storage = TrackedRwLock::new(LockOrder::Storage, 0u32);
        let registry = TrackedRwLock::new(LockOrder::ValidatorRegistry, 0u32);
        let consensus = TrackedRwLock::new(LockOrder::Consensus, 0u32);
        let g_s = storage.read();
        let g_r = registry.read();
        let g_c = consensus.write();
        drop(g_c);
        drop(g_r);
        drop(g_s);
        // Sequential (drop-before-acquire) must also be fine.
        let _ = storage.read();
    }

    #[test]
    #[should_panic(expected = "LOCK ORDER VIOLATION")]
    fn inverted_ordering_panics() {
        let storage = TrackedRwLock::new(LockOrder::Storage, 0u32);
        let registry = TrackedRwLock::new(LockOrder::ValidatorRegistry, 0u32);
        let _held = registry.read(); // rank 3
        // Acquiring storage (2) while holding registry (3) inverts the order.
        let _bad = storage.read();
    }

    #[test]
    #[should_panic(expected = "LOCK ORDER VIOLATION")]
    fn recursive_same_rank_read_panics() {
        // Reproduces the 0.138.0 get_validator_list bug shape: a consensus read
        // taken recursively while a consensus read is already held.
        let consensus = TrackedRwLock::new(LockOrder::Consensus, 0u32);
        let _outer = consensus.read();
        let _inner = consensus.read(); // rank 4 while holding rank 4 → violation
    }

    #[test]
    fn drop_releases_the_rank() {
        let consensus = TrackedRwLock::new(LockOrder::Consensus, 0u32);
        {
            let _g = consensus.read();
            assert_eq!(held_locks(), vec![LockOrder::Consensus]);
        }
        assert!(held_locks().is_empty(), "guard drop must clear the held stack");
        // A fresh acquire after the drop is legal (not a recursive violation).
        let _g2 = consensus.read();
    }
}
