// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Metadata entries for NOBLE transactions.

use serde::{Deserialize, Serialize};

use crate::constants::{MAX_METADATA_KEY_LEN, MAX_METADATA_VALUE_LEN};
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

    // T9: check for duplicate keys
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            if entries[i].key == entries[j].key {
                return Err(ValidationError::DuplicateMetadataKey(
                    entries[i].key.clone(),
                ));
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
}
