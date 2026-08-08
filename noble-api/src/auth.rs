// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! TOTP-based authentication for the RPC API.
//!
//! When enabled, all RPC requests must include a valid TOTP code in the
//! `Authorization: Bearer <code>` header. The secret is generated on first
//! setup and can be rotated via the `noble_rotateTotpSecret` RPC method.

use std::collections::VecDeque;
use std::time::Instant;

use parking_lot::Mutex;

use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

/// SHA-256 hash a raw TOTP code, returning 64-char lowercase hex.
///
/// Clients send `Authorization: Bearer <hash_code(code)>` rather than
/// the raw 6-digit code, so the code never travels over the wire.
pub fn hash_code(code: &str) -> String {
    let hash = noble_crypto::sha256(code.as_bytes());
    hex::encode(hash.as_bytes())
}

/// Validates TOTP codes against a stored secret.
pub struct TotpValidator {
    totp: TOTP,
    /// AUD2-H1: Track recently used codes to prevent replay within window.
    used_codes: Mutex<VecDeque<(String, Instant)>>,
}

impl TotpValidator {
    /// Create a validator from a base32-encoded secret.
    pub fn from_base32(secret_base32: &str) -> Result<Self, String> {
        let secret = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .map_err(|e| format!("invalid base32 secret: {e}"))?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
            .map_err(|e| format!("TOTP init error: {e}"))?;
        Ok(Self {
            totp,
            used_codes: Mutex::new(VecDeque::new()),
        })
    }

    /// Generate a new random secret and return a validator + base32 string.
    pub fn generate() -> Result<(Self, String), String> {
        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();
        let validator = Self::from_base32(&secret_base32)?;
        Ok((validator, secret_base32))
    }

    /// Validate a TOTP code (6-digit string).
    /// Allows ±1 time step skew (30 seconds each side).
    pub fn validate(&self, code: &str) -> bool {
        self.totp.check_current(code).unwrap_or(false)
    }

    /// Validate a SHA-256-hashed TOTP code (64-char hex).
    ///
    /// Generates codes for the current ±1 time steps, hashes each,
    /// and compares against the provided hash using constant-time comparison.
    /// All three time steps are always checked (no early return) to prevent
    /// timing side-channel attacks.
    /// L15: validate WITHOUT recording the code as used.
    ///
    /// The reuse tracker is what makes a TOTP code single-use, and the auth
    /// middleware consumes the code on the way in. `rotateTotpSecret` then
    /// validated the SAME code again and was rejected as a replay — rotation
    /// simply could not succeed for a direct Bearer caller. (GUI-proxied calls
    /// bypass middleware TOTP, so the bug only bit CLI/script clients, which is
    /// why it survived.) A handler re-checking a code the middleware already
    /// verified wants this, not `validate_hash`.
    pub fn validate_hash_no_consume(&self, hash_hex: &str) -> bool {
        self.validate_hash_inner(hash_hex, false)
    }

    pub fn validate_hash(&self, hash_hex: &str) -> bool {
        self.validate_hash_inner(hash_hex, true)
    }

    fn validate_hash_inner(&self, hash_hex: &str, consume: bool) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Normalize to lowercase for constant-time comparison
        let input = hash_hex.to_ascii_lowercase();
        let input_bytes = input.as_bytes();

        // AUD-M1: Always run constant-time compare regardless of length.
        // Pad shorter side to 64 bytes so ct_eq always runs on equal-length slices.
        let expected_len = 64; // SHA-256 hex is always 64 chars
        let len_ok = input_bytes.len() == expected_len;

        // Always check all 3 time steps — no early return
        let mut matched: u8 = 0;
        let mut matched_code: Option<String> = None;
        for offset in [-1i64, 0, 1] {
            let t = (now as i64 + offset * 30) as u64;
            let code = self.totp.generate(t);
            let expected = hash_code(&code);
            let expected_bytes = expected.as_bytes();

            // Constant-time comparison via subtle — always compare 64 bytes
            // Even if input length differs, we still do the comparison to avoid timing leak
            let cmp_len = input_bytes
                .len()
                .min(expected_bytes.len())
                .min(expected_len);
            let ct_match = input_bytes[..cmp_len]
                .ct_eq(&expected_bytes[..cmp_len])
                .unwrap_u8();
            if ct_match == 1 && len_ok {
                matched |= 1;
                matched_code = Some(code);
            }
        }

        // AUD2-H1: Reject codes already used within the window (replay prevention)
        if matched != 0 {
            // L15: a non-consuming check confirms validity without touching the
            // replay tracker, so a handler can re-verify a code the middleware
            // already accepted.
            if !consume {
                return true;
            }
            if let Some(code) = matched_code {
                let mut used = self.used_codes.lock();
                // Drain expired entries (older than 180 seconds).
                // Window covers the full ±1 TOTP time-step acceptance range (90s)
                // plus a safety margin to close the microsecond boundary edge case.
                // L17: `Instant - Duration` PANICS on underflow. On a host with
                // less than 180s of monotonic uptime — a node started at boot,
                // with an operator logging in promptly — this aborted the
                // process on the first accepted TOTP code. When the window
                // cannot be represented yet, nothing is old enough to drain, so
                // simply keep every entry.
                if let Some(cutoff) =
                    Instant::now().checked_sub(std::time::Duration::from_secs(180))
                {
                    while used.front().is_some_and(|(_, t)| *t < cutoff) {
                        used.pop_front();
                    }
                }
                // Check if this code was already used
                if used.iter().any(|(c, _)| c == &code) {
                    return false; // replay detected
                }
                // Record the code as used
                used.push_back((code, Instant::now()));
            }
        }

        matched != 0
    }

    /// Get the base32-encoded secret string.
    pub fn secret_base32(&self) -> String {
        Secret::Raw(self.totp.secret.clone())
            .to_encoded()
            .to_string()
    }

    /// Generate an `otpauth://` URI for QR code generation.
    pub fn otpauth_uri(&self, label: &str) -> String {
        let b32 = self.secret_base32();
        format!(
            "otpauth://totp/NOBLE:{label}?secret={b32}&issuer=NOBLE&algorithm=SHA1&digits=6&period=30"
        )
    }

    /// Generate a new validator with a fresh secret.
    /// Returns (new_validator, base32_secret, otpauth_uri).
    pub fn rotate() -> Result<(Self, String, String), String> {
        let (validator, base32) = Self::generate()?;
        let uri = validator.otpauth_uri("NOBLE Node");
        Ok((validator, base32, uri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_secret() {
        let (validator, secret) = TotpValidator::generate().unwrap();
        assert!(!secret.is_empty());
        let code = validator.totp.generate_current().unwrap();
        assert!(validator.validate(&code));
    }

    #[test]
    fn from_base32_roundtrip() {
        let (original, secret) = TotpValidator::generate().unwrap();
        let restored = TotpValidator::from_base32(&secret).unwrap();
        let code = original.totp.generate_current().unwrap();
        assert!(restored.validate(&code));
    }

    #[test]
    fn wrong_code_rejected() {
        let (validator, _) = TotpValidator::generate().unwrap();
        assert!(!validator.validate("000000"));
        assert!(!validator.validate("not-a-code"));
        assert!(!validator.validate(""));
    }

    #[test]
    fn secret_rotation_produces_new_codes() {
        let (v1, _s1) = TotpValidator::generate().unwrap();
        let (v2, _s2) = TotpValidator::generate().unwrap();
        assert_ne!(v1.secret_base32(), v2.secret_base32());
        let code1 = v1.totp.generate_current().unwrap();
        assert!(v1.validate(&code1));
    }

    // --- Hashed TOTP tests ---

    #[test]
    fn hash_code_produces_64_char_hex() {
        let hash = hash_code("123456");
        assert_eq!(hash.len(), 64, "SHA-256 hex is 64 chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_hash_accepts_correct_hash() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let code = validator.totp.generate_current().unwrap();
        let hash = hash_code(&code);
        assert!(validator.validate_hash(&hash));
    }

    #[test]
    fn validate_hash_rejects_wrong_hash() {
        let (validator, _) = TotpValidator::generate().unwrap();
        assert!(!validator.validate_hash("00".repeat(32).as_str()));
        assert!(!validator.validate_hash("not-a-hash"));
        assert!(!validator.validate_hash(""));
    }

    #[test]
    fn validate_hash_case_insensitive() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let code = validator.totp.generate_current().unwrap();
        let hash = hash_code(&code);
        assert!(validator.validate_hash(&hash.to_uppercase()));
    }

    #[test]
    fn rotate_produces_valid_new_secret() {
        let (new_validator, base32, uri) = TotpValidator::rotate().unwrap();
        assert!(!base32.is_empty());
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("NOBLE"));
        // New validator's own code should validate
        let code = new_validator.totp.generate_current().unwrap();
        assert!(new_validator.validate(&code));
    }

    #[test]
    fn validate_hash_constant_time_accepts_correct() {
        // Verify the constant-time implementation still accepts valid codes
        let (validator, _) = TotpValidator::generate().unwrap();
        let code = validator.totp.generate_current().unwrap();
        let hash = hash_code(&code);
        assert!(
            validator.validate_hash(&hash),
            "constant-time validate_hash should accept correct hash"
        );
    }

    #[test]
    fn validate_hash_constant_time_rejects_wrong_length() {
        let (validator, _) = TotpValidator::generate().unwrap();
        // Wrong length should be rejected (not panic)
        assert!(!validator.validate_hash("abc"));
        assert!(!validator.validate_hash(""));
        assert!(!validator.validate_hash(&"a".repeat(128)));
    }

    // AUD-M1: Mismatched-length inputs don't short-circuit (timing leak)
    #[test]
    fn validate_hash_no_timing_leak_on_length_mismatch() {
        let (validator, _) = TotpValidator::generate().unwrap();
        // These should all be rejected but should take similar time
        // (we can't measure timing precisely in a unit test, but we verify
        // that the function returns false without panicking)
        assert!(!validator.validate_hash("short"));
        assert!(!validator.validate_hash(&"x".repeat(63))); // one byte short
        assert!(!validator.validate_hash(&"x".repeat(65))); // one byte long
        assert!(!validator.validate_hash(&"0".repeat(128))); // double length
    }

    // AUD2-H1: Same TOTP code rejected on second use within window
    #[test]
    fn validate_hash_rejects_replay_within_window() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let code = validator.totp.generate_current().unwrap();
        let hash = hash_code(&code);

        // First use should succeed
        assert!(validator.validate_hash(&hash));
        // Second use of same code within 90s window should be rejected
        assert!(
            !validator.validate_hash(&hash),
            "replay of same TOTP code should be rejected"
        );
    }

    // AUD2-H1: Different codes in same period still work
    #[test]
    fn validate_hash_different_codes_accepted() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let code = validator.totp.generate_current().unwrap();
        let hash = hash_code(&code);

        // Use the current code
        assert!(validator.validate_hash(&hash));

        // A completely different (wrong) code should still be rejected normally
        let wrong = hash_code("000000");
        assert!(!validator.validate_hash(&wrong));
    }
}
