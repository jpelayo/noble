// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! TOTP-based authentication for the RPC API.
//!
//! When enabled, all RPC requests must include a valid TOTP code in the
//! `Authorization: Bearer <code>` header. The secret is generated on first
//! setup and can be rotated via the `noble_rotateTotpSecret` RPC method.

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
}

impl TotpValidator {
    /// Create a validator from a base32-encoded secret.
    pub fn from_base32(secret_base32: &str) -> Result<Self, String> {
        let secret = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .map_err(|e| format!("invalid base32 secret: {e}"))?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
            .map_err(|e| format!("TOTP init error: {e}"))?;
        Ok(Self { totp })
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
    pub fn validate_hash(&self, hash_hex: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Normalize to lowercase for constant-time comparison
        let input = hash_hex.to_ascii_lowercase();
        let input_bytes = input.as_bytes();

        // Always check all 3 time steps — no early return
        let mut matched: u8 = 0;
        for offset in [-1i64, 0, 1] {
            let t = (now as i64 + offset * 30) as u64;
            let code = self.totp.generate(t);
            let expected = hash_code(&code);
            let expected_bytes = expected.as_bytes();

            // Constant-time comparison via subtle
            if input_bytes.len() == expected_bytes.len() {
                matched |= input_bytes.ct_eq(expected_bytes).unwrap_u8();
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
}
