// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! GUI admin lock: server-side session store + helpers for the dashboard login
//! wall (port 8785).
//!
//! When the admin enables the GUI lock, the GUI server requires a valid TOTP
//! code at login, then issues an opaque session cookie. Subsequent requests are
//! gated by the session — NOT by per-request TOTP — which avoids the 30-second
//! rotation + replay-protection constraints that make per-request TOTP unusable
//! for a continuous browser session.
//!
//! Sessions are in-memory only: a node restart clears them all (everyone must
//! re-login). They carry NO server-side timeout — a session lives until explicit
//! logout or the browser drops the session cookie (browser close). `MAX_SESSIONS`
//! is a memory bound (evict-oldest), not a user-visible expiry.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use rand::RngCore;

use noble_api::state::SharedTotpSlot;

/// Cookie name for the GUI admin-lock session.
pub const SESSION_COOKIE: &str = "noble_gui_session";

/// Upper bound on concurrently-stored sessions. On overflow the least-recently
/// created session is evicted. This is a memory bound, not a timeout — reaching
/// it would take this many distinct logins without browser-close/logout.
const MAX_SESSIONS: usize = 256;

/// Per-IP login brute-force policy: after `MAX_FAILURES` consecutive failures,
/// lock the IP out for an exponentially-growing window capped at `LOCKOUT_MAX`.
const MAX_FAILURES: u32 = 5;
const LOCKOUT_BASE_SECS: u64 = 30;
const LOCKOUT_MAX_SECS: u64 = 300;

struct SessionMeta {
    #[allow(dead_code)]
    created_at: Instant,
    /// Updated on each validated request for observability only — never used to
    /// expire a session (the lock has no server-side timeout).
    last_seen: Instant,
}

/// In-memory store of opaque GUI sessions, keyed by a 256-bit random token.
pub struct GuiSessionStore {
    sessions: RwLock<HashMap<[u8; 32], SessionMeta>>,
    /// Creation order, for evict-oldest when over `MAX_SESSIONS`. Kept in sync
    /// with `sessions`. Lock order: always `order` before `sessions`.
    order: Mutex<VecDeque<[u8; 32]>>,
}

impl GuiSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            order: Mutex::new(VecDeque::new()),
        }
    }

    /// Mint a new session and return its hex token (the cookie value).
    pub fn create(&self) -> String {
        let mut token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let now = Instant::now();

        let mut order = self.order.lock();
        let mut sessions = self.sessions.write();
        while sessions.len() >= MAX_SESSIONS {
            match order.pop_front() {
                Some(old) => {
                    sessions.remove(&old);
                }
                None => break,
            }
        }
        sessions.insert(
            token,
            SessionMeta {
                created_at: now,
                last_seen: now,
            },
        );
        order.push_back(token);
        drop(sessions);
        drop(order);

        hex::encode(token)
    }

    /// Validate a presented hex token. Returns `true` if it names a live session
    /// (and refreshes `last_seen`). A 256-bit token is high-entropy enough that
    /// the `HashMap` lookup is not a practical timing oracle.
    pub fn validate(&self, hex_token: &str) -> bool {
        let key = match decode_token(hex_token) {
            Some(k) => k,
            None => return false,
        };
        let mut sessions = self.sessions.write();
        if let Some(meta) = sessions.get_mut(&key) {
            meta.last_seen = Instant::now();
            true
        } else {
            false
        }
    }

    /// Revoke a session (logout). Idempotent.
    pub fn remove(&self, hex_token: &str) {
        if let Some(key) = decode_token(hex_token) {
            let mut order = self.order.lock();
            let mut sessions = self.sessions.write();
            sessions.remove(&key);
            order.retain(|k| *k != key);
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for GuiSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a 64-char hex token into raw bytes. Rejects wrong length / non-hex.
fn decode_token(hex_token: &str) -> Option<[u8; 32]> {
    if hex_token.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex_token).ok()?;
    bytes.try_into().ok()
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/// Extract the session token from a `Cookie` header value, handling multiple
/// `name=value` pairs separated by `; `.
pub fn parse_session_cookie(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        if k.trim() == SESSION_COOKIE {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// `Set-Cookie` value that establishes the session. No `Max-Age`/`Expires` →
/// a session cookie that dies on browser close. `Secure` only under TLS (else
/// the browser drops it over plain HTTP and login would silently fail).
pub fn set_cookie_value(token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{secure_attr}")
}

/// `Set-Cookie` value that clears the session (logout).
pub fn clear_cookie_value(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/{secure_attr}")
}

// ---------------------------------------------------------------------------
// Login brute-force limiter
// ---------------------------------------------------------------------------

struct AttemptState {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Per-IP login attempt limiter. Online TOTP guessing is already bounded by the
/// 10^6 code space + ~90s window + replay protection; this is defense-in-depth.
pub struct LoginLimiter {
    attempts: Mutex<HashMap<IpAddr, AttemptState>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// If the IP is currently locked out, return `Some(retry_after_secs)`.
    pub fn locked_for(&self, ip: IpAddr) -> Option<u64> {
        let attempts = self.attempts.lock();
        let st = attempts.get(&ip)?;
        let until = st.locked_until?;
        let now = Instant::now();
        if until > now {
            Some((until - now).as_secs().max(1))
        } else {
            None
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut attempts = self.attempts.lock();
        let st = attempts.entry(ip).or_insert(AttemptState {
            failures: 0,
            locked_until: None,
        });
        st.failures += 1;
        if st.failures >= MAX_FAILURES {
            let over = (st.failures - MAX_FAILURES).min(4);
            let secs = (LOCKOUT_BASE_SECS << over).min(LOCKOUT_MAX_SECS);
            st.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.attempts.lock().remove(&ip);
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Lock state bundle (passed into the GUI server)
// ---------------------------------------------------------------------------

/// Everything the GUI server needs to enforce the admin lock. Cheap to clone
/// (all shared `Arc`s) — used as Axum handler/middleware state.
#[derive(Clone)]
pub struct GuiLockState {
    /// Live on/off flag, shared with `ApiState` for hot-reload via `setConfigValue`.
    pub enabled: Arc<AtomicBool>,
    /// Live TOTP validator handle (survives runtime enable/rotate).
    pub totp_slot: SharedTotpSlot,
    pub store: Arc<GuiSessionStore>,
    pub limiter: Arc<LoginLimiter>,
    /// Whether to set the `Secure` cookie attribute (true when the GUI uses TLS).
    pub secure_cookie: bool,
    /// Per-boot proxy-trust secret the gate attaches to session-authenticated
    /// requests so the loopback RPC accepts them under any `totp_scope`. Same
    /// value as `ApiState.gui_proxy_secret`.
    pub proxy_secret: Arc<String>,
}

impl GuiLockState {
    pub fn new(
        enabled: Arc<AtomicBool>,
        totp_slot: SharedTotpSlot,
        secure_cookie: bool,
        proxy_secret: Arc<String>,
    ) -> Self {
        Self {
            enabled,
            totp_slot,
            store: Arc::new(GuiSessionStore::new()),
            limiter: Arc::new(LoginLimiter::new()),
            secure_cookie,
            proxy_secret,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Validate a SHA-256-hashed TOTP code against the live validator.
    /// `Ok(true)` = valid, `Ok(false)` = wrong code, `Err(())` = no validator
    /// available (lock enabled without TOTP — a misconfiguration).
    pub fn validate_totp(&self, code_hash: &str) -> Result<bool, ()> {
        let validator = self.totp_slot.read().clone();
        match validator {
            Some(inner) => Ok(inner.read().validate_hash(code_hash)),
            None => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn create_yields_unique_64hex_tokens() {
        let store = GuiSessionStore::new();
        let a = store.create();
        let b = store.create();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "tokens must be unique");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn insert_validate_remove() {
        let store = GuiSessionStore::new();
        let token = store.create();
        assert!(store.validate(&token));
        store.remove(&token);
        assert!(!store.validate(&token));
        assert!(store.is_empty());
    }

    #[test]
    fn validate_rejects_garbage() {
        let store = GuiSessionStore::new();
        assert!(!store.validate(""));
        assert!(!store.validate("not-hex"));
        assert!(!store.validate(&"a".repeat(63))); // wrong length
        assert!(!store.validate(&"zz".repeat(32))); // 64 chars but non-hex
        assert!(!store.validate(&"ab".repeat(32))); // valid hex, unknown session
    }

    #[test]
    fn cap_evicts_oldest() {
        let store = GuiSessionStore::new();
        let first = store.create();
        for _ in 0..MAX_SESSIONS {
            store.create();
        }
        assert!(store.len() <= MAX_SESSIONS, "store must stay bounded");
        assert!(
            !store.validate(&first),
            "the oldest session must have been evicted"
        );
    }

    #[test]
    fn parse_cookie_handles_multiple_pairs() {
        let hdr = "theme=dark; noble_gui_session=abc123; other=1";
        assert_eq!(parse_session_cookie(hdr), Some("abc123"));
        assert_eq!(parse_session_cookie("noble_gui_session=xyz"), Some("xyz"));
        assert_eq!(parse_session_cookie("theme=dark; other=1"), None);
        assert_eq!(parse_session_cookie(""), None);
    }

    #[test]
    fn cookie_secure_flag_toggles() {
        assert!(set_cookie_value("tok", true).contains("; Secure"));
        assert!(!set_cookie_value("tok", false).contains("Secure"));
        assert!(set_cookie_value("tok", true).contains("HttpOnly"));
        assert!(set_cookie_value("tok", true).contains("SameSite=Strict"));
        // Session cookie: must NOT carry an expiry.
        assert!(!set_cookie_value("tok", true).contains("Max-Age"));
        assert!(!set_cookie_value("tok", true).contains("Expires"));
        // Clear cookie expires immediately.
        assert!(clear_cookie_value(false).contains("Max-Age=0"));
    }

    #[test]
    fn limiter_locks_after_failures_and_resets_on_success() {
        let limiter = LoginLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(limiter.locked_for(ip).is_none());
        for _ in 0..MAX_FAILURES {
            limiter.record_failure(ip);
        }
        assert!(
            limiter.locked_for(ip).is_some(),
            "IP must be locked after {MAX_FAILURES} failures"
        );
        limiter.record_success(ip);
        assert!(
            limiter.locked_for(ip).is_none(),
            "success must clear the lockout"
        );
    }
}
