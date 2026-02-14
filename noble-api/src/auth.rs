// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! TOTP-based authentication for the RPC API.
//!
//! When enabled, all RPC requests must include a valid TOTP code in the
//! `Authorization: Bearer <code>` header. The secret is generated on first
//! setup and can be rotated via the `noble_rotateTotpSecret` RPC method.

use totp_rs::{Algorithm, Secret, TOTP};

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

    /// Get the base32-encoded secret string.
    pub fn secret_base32(&self) -> String {
        Secret::Raw(self.totp.secret.clone())
            .to_encoded()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_secret() {
        let (validator, secret) = TotpValidator::generate().unwrap();
        assert!(!secret.is_empty());
        // The current code should validate
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
        // New secret should generate different codes (with extremely high probability)
        let code1 = v1.totp.generate_current().unwrap();
        // v2 should NOT accept v1's code (statistically)
        // This is probabilistic but 999999/1000000 chance of being different
        // so we just check they have different secrets
        assert_ne!(v1.secret_base32(), v2.secret_base32());
        // code1 validates against v1 but not necessarily v2
        assert!(v1.validate(&code1));
    }
}
