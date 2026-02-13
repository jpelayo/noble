// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet lock/unlock state with optional auto-lock timeout.

use std::time::{Duration, Instant};

/// Tracks wallet lock/unlock state with optional auto-lock timeout.
pub struct WalletState {
    unlocked_until: Option<Instant>,
    max_timeout_secs: u64,
}

impl WalletState {
    /// Create a new wallet state with the given maximum timeout.
    pub fn new(max_timeout_secs: u64) -> Self {
        Self {
            unlocked_until: None,
            max_timeout_secs,
        }
    }

    /// Unlock the wallet for `timeout_secs` seconds (clamped to `max_timeout_secs`).
    /// Returns the estimated unix timestamp at which the lock will expire.
    pub fn unlock(&mut self, timeout_secs: u64) -> u64 {
        let timeout = timeout_secs.min(self.max_timeout_secs);
        let until = Instant::now() + Duration::from_secs(timeout);
        self.unlocked_until = Some(until);

        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + timeout
    }

    /// Immediately lock the wallet.
    pub fn lock(&mut self) {
        self.unlocked_until = None;
    }

    /// Returns `true` if the wallet is currently unlocked (timeout not expired).
    pub fn is_unlocked(&self) -> bool {
        match self.unlocked_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// Returns the estimated unix timestamp at which the wallet will auto-lock,
    /// or `None` if the wallet is locked.
    pub fn expires_at_unix(&self) -> Option<u64> {
        self.unlocked_until.map(|until| {
            let now = Instant::now();
            if until > now {
                let remaining = until.duration_since(now).as_secs();
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + remaining
            } else {
                0
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_state_unlock_expire() {
        let mut state = WalletState::new(3600);
        assert!(!state.is_unlocked());
        assert!(state.expires_at_unix().is_none());

        let expires = state.unlock(60);
        assert!(state.is_unlocked());
        assert!(expires > 0);
        assert!(state.expires_at_unix().is_some());
    }

    #[test]
    fn wallet_state_manual_lock() {
        let mut state = WalletState::new(3600);
        state.unlock(300);
        assert!(state.is_unlocked());

        state.lock();
        assert!(!state.is_unlocked());
        assert!(state.expires_at_unix().is_none());
    }

    #[test]
    fn wallet_state_clamps_to_max() {
        let mut state = WalletState::new(60);
        // Request 3600 seconds but max is 60.
        let expires = state.unlock(3600);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Should expire within ~60 seconds, not ~3600.
        assert!(expires <= now_unix + 61);
    }
}
