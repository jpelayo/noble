// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// The app's lock state machine.
///
/// Transitions:
/// - `unlocked` ↔ `softLocked` (biometric/PIN re-auth)
/// - `softLocked` ↔ `hardLocked` (master password / system auth)
public enum AppLockState: String, Codable, Sendable {
    /// App is fully accessible.
    case unlocked
    /// App requires biometric or PIN to resume (background timeout).
    case softLocked
    /// App requires master password (explicit lock or initial launch).
    case hardLocked
}
