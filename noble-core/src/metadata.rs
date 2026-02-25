// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Metadata entries for NOBLE transactions.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::constants::{
    MAX_METADATA_KEY_LEN, MAX_METADATA_VALUE_LEN, META_KEY_PREV_CHECKSUM, META_KEY_VERSION,
};
use crate::error::ValidationError;

/// A key-value metadata entry attached to a transaction.
///
/// Keys are UTF-8 strings (1-64 bytes), values are opaque byte arrays (1-256 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataEntry {
    /// Metadata key (1-64 bytes, UTF-8).
    pub key: String,
    /// Metadata value (1-256 bytes, opaque).
    pub value: Vec<u8>,
}

impl MetadataEntry {
    /// Create a new metadata entry, validating bounds.
    pub fn new(key: String, value: Vec<u8>) -> Result<Self, ValidationError> {
        let entry = Self { key, value };
        entry.validate()?;
        Ok(entry)
    }

    /// Validate that this entry's key and value are within protocol bounds (T8).
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.key.is_empty() || self.key.len() > MAX_METADATA_KEY_LEN {
            return Err(ValidationError::MetadataBounds(format!(
                "key length {} out of range [1, {}]",
                self.key.len(),
                MAX_METADATA_KEY_LEN
            )));
        }

        if self.value.is_empty() || self.value.len() > MAX_METADATA_VALUE_LEN {
            return Err(ValidationError::MetadataBounds(format!(
                "value length {} out of range [1, {}]",
                self.value.len(),
                MAX_METADATA_VALUE_LEN
            )));
        }

        Ok(())
    }
}

/// Validate a list of metadata entries: individual bounds (T8) and uniqueness (T9).
pub fn validate_metadata(entries: &[MetadataEntry]) -> Result<(), ValidationError> {
    for entry in entries {
        entry.validate()?;
    }

    // T9: check for duplicate keys (O(n) via HashSet)
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        if !seen.insert(&entry.key) {
            return Err(ValidationError::DuplicateMetadataKey(entry.key.clone()));
        }
    }

    Ok(())
}

/// Validate version metadata consistency (T29/T30).
///
/// Rules (stateless — no chain lookup needed):
/// - If `doc:prev_checksum` is present: must be valid 64-char hex, and `doc:version` must be > 1
/// - If `doc:version` is present: must parse as positive integer 1..=u32::MAX;
///   if value is "1", `doc:prev_checksum` must NOT be present
/// - If neither key is present → no constraints (backward compatible)
pub fn validate_version_metadata(entries: &[MetadataEntry]) -> Result<(), ValidationError> {
    let prev_checksum = entries.iter().find(|m| m.key == META_KEY_PREV_CHECKSUM);
    let version = entries.iter().find(|m| m.key == META_KEY_VERSION);

    // If neither key is present, nothing to validate
    if prev_checksum.is_none() && version.is_none() {
        return Ok(());
    }

    // Validate doc:version if present
    if let Some(ver_entry) = version {
        let ver_str = std::str::from_utf8(&ver_entry.value).map_err(|_| {
            ValidationError::VersionMetadataInconsistent(
                "doc:version value is not valid UTF-8".into(),
            )
        })?;
        let ver_num: u32 = ver_str.parse().map_err(|_| {
            ValidationError::VersionMetadataInconsistent(format!(
                "doc:version must be a positive integer, got '{ver_str}'"
            ))
        })?;
        if ver_num == 0 {
            return Err(ValidationError::VersionMetadataInconsistent(
                "doc:version must be >= 1".into(),
            ));
        }
        // v1 must NOT have prev_checksum
        if ver_num == 1 && prev_checksum.is_some() {
            return Err(ValidationError::VersionMetadataInconsistent(
                "doc:version=1 must not have doc:prev_checksum".into(),
            ));
        }
    }

    // Validate doc:prev_checksum if present
    if let Some(prev_entry) = prev_checksum {
        let prev_str = std::str::from_utf8(&prev_entry.value)
            .map_err(|_| ValidationError::InvalidPrevChecksum("value is not valid UTF-8".into()))?;
        // Must be exactly 64 hex characters
        if prev_str.len() != 64 {
            return Err(ValidationError::InvalidPrevChecksum(format!(
                "expected 64 hex chars, got {}",
                prev_str.len()
            )));
        }
        if !prev_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError::InvalidPrevChecksum(
                "contains non-hex characters".into(),
            ));
        }
        // doc:version must also be present and > 1
        match version {
            None => {
                return Err(ValidationError::VersionMetadataInconsistent(
                    "doc:prev_checksum requires doc:version".into(),
                ));
            }
            Some(ver_entry) => {
                let ver_str = std::str::from_utf8(&ver_entry.value).unwrap_or("?");
                let ver_num: u32 = ver_str.parse().unwrap_or(0);
                if ver_num <= 1 {
                    return Err(ValidationError::VersionMetadataInconsistent(
                        "doc:prev_checksum requires doc:version > 1".into(),
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_entry() {
        let entry = MetadataEntry::new("doc_type".into(), b"test_report".to_vec());
        assert!(entry.is_ok());
    }

    #[test]
    fn empty_key_rejected() {
        let entry = MetadataEntry::new(String::new(), vec![1]);
        assert!(matches!(entry, Err(ValidationError::MetadataBounds(_))));
    }

    #[test]
    fn key_too_long_rejected() {
        let long_key = "x".repeat(MAX_METADATA_KEY_LEN + 1);
        let entry = MetadataEntry::new(long_key, vec![1]);
        assert!(matches!(entry, Err(ValidationError::MetadataBounds(_))));
    }

    #[test]
    fn key_at_max_length_accepted() {
        let max_key = "x".repeat(MAX_METADATA_KEY_LEN);
        let entry = MetadataEntry::new(max_key, vec![1]);
        assert!(entry.is_ok());
    }

    #[test]
    fn empty_value_rejected() {
        let entry = MetadataEntry::new("key".into(), vec![]);
        assert!(matches!(entry, Err(ValidationError::MetadataBounds(_))));
    }

    #[test]
    fn value_too_long_rejected() {
        let long_value = vec![0u8; MAX_METADATA_VALUE_LEN + 1];
        let entry = MetadataEntry::new("key".into(), long_value);
        assert!(matches!(entry, Err(ValidationError::MetadataBounds(_))));
    }

    #[test]
    fn value_at_max_length_accepted() {
        let max_value = vec![0u8; MAX_METADATA_VALUE_LEN];
        let entry = MetadataEntry::new("key".into(), max_value);
        assert!(entry.is_ok());
    }

    #[test]
    fn duplicate_keys_rejected() {
        let entries = vec![
            MetadataEntry {
                key: "doc_type".into(),
                value: b"report".to_vec(),
            },
            MetadataEntry {
                key: "doc_type".into(),
                value: b"certificate".to_vec(),
            },
        ];
        assert!(matches!(
            validate_metadata(&entries),
            Err(ValidationError::DuplicateMetadataKey(_))
        ));
    }

    #[test]
    fn unique_keys_accepted() {
        let entries = vec![
            MetadataEntry {
                key: "doc_type".into(),
                value: b"report".to_vec(),
            },
            MetadataEntry {
                key: "lab_id".into(),
                value: b"LAB-001".to_vec(),
            },
        ];
        assert!(validate_metadata(&entries).is_ok());
    }

    #[test]
    fn empty_metadata_accepted() {
        assert!(validate_metadata(&[]).is_ok());
    }

    #[test]
    fn cbor_roundtrip() {
        use noble_codec::NobleCbor;
        let entry = MetadataEntry {
            key: "standard".into(),
            value: b"ISO17025".to_vec(),
        };
        let bytes = entry.to_cbor().unwrap();
        let decoded = MetadataEntry::from_cbor(&bytes).unwrap();
        assert_eq!(entry, decoded);
    }

    // --- Version metadata validation (T29/T30) ---

    #[test]
    fn version_metadata_absent_is_ok() {
        let entries = vec![MetadataEntry {
            key: "doc_type".into(),
            value: b"report".to_vec(),
        }];
        assert!(validate_version_metadata(&entries).is_ok());
        assert!(validate_version_metadata(&[]).is_ok());
    }

    #[test]
    fn version_v1_explicit_ok() {
        let entries = vec![MetadataEntry {
            key: META_KEY_VERSION.into(),
            value: b"1".to_vec(),
        }];
        assert!(validate_version_metadata(&entries).is_ok());
    }

    #[test]
    fn version_v2_with_prev_ok() {
        let prev_hex = "aa".repeat(32); // 64 hex chars
        let entries = vec![
            MetadataEntry {
                key: META_KEY_VERSION.into(),
                value: b"2".to_vec(),
            },
            MetadataEntry {
                key: META_KEY_PREV_CHECKSUM.into(),
                value: prev_hex.as_bytes().to_vec(),
            },
        ];
        assert!(validate_version_metadata(&entries).is_ok());
    }

    #[test]
    fn version_prev_without_version_rejected() {
        let prev_hex = "bb".repeat(32);
        let entries = vec![MetadataEntry {
            key: META_KEY_PREV_CHECKSUM.into(),
            value: prev_hex.as_bytes().to_vec(),
        }];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::VersionMetadataInconsistent(_))
        ));
    }

    #[test]
    fn version_v1_with_prev_rejected() {
        let prev_hex = "cc".repeat(32);
        let entries = vec![
            MetadataEntry {
                key: META_KEY_VERSION.into(),
                value: b"1".to_vec(),
            },
            MetadataEntry {
                key: META_KEY_PREV_CHECKSUM.into(),
                value: prev_hex.as_bytes().to_vec(),
            },
        ];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::VersionMetadataInconsistent(_))
        ));
    }

    #[test]
    fn version_prev_bad_hex_rejected() {
        let bad_hex = "zz".repeat(32); // non-hex
        let entries = vec![
            MetadataEntry {
                key: META_KEY_VERSION.into(),
                value: b"2".to_vec(),
            },
            MetadataEntry {
                key: META_KEY_PREV_CHECKSUM.into(),
                value: bad_hex.as_bytes().to_vec(),
            },
        ];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::InvalidPrevChecksum(_))
        ));
    }

    #[test]
    fn version_prev_wrong_length_rejected() {
        let short_hex = "aa".repeat(31); // 62 chars, not 64
        let entries = vec![
            MetadataEntry {
                key: META_KEY_VERSION.into(),
                value: b"2".to_vec(),
            },
            MetadataEntry {
                key: META_KEY_PREV_CHECKSUM.into(),
                value: short_hex.as_bytes().to_vec(),
            },
        ];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::InvalidPrevChecksum(_))
        ));
    }

    #[test]
    fn version_zero_rejected() {
        let entries = vec![MetadataEntry {
            key: META_KEY_VERSION.into(),
            value: b"0".to_vec(),
        }];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::VersionMetadataInconsistent(_))
        ));
    }

    #[test]
    fn version_non_numeric_rejected() {
        let entries = vec![MetadataEntry {
            key: META_KEY_VERSION.into(),
            value: b"abc".to_vec(),
        }];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::VersionMetadataInconsistent(_))
        ));
    }

    #[test]
    fn version_negative_rejected() {
        let entries = vec![MetadataEntry {
            key: META_KEY_VERSION.into(),
            value: b"-1".to_vec(),
        }];
        assert!(matches!(
            validate_version_metadata(&entries),
            Err(ValidationError::VersionMetadataInconsistent(_))
        ));
    }
}
