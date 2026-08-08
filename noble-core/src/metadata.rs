// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Metadata entries for NOBLE transactions.


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

/// Total ordering over metadata entries: by key, then by value.
///
/// Ordering by key **alone** is not total, because duplicate keys are legal
/// (T9 removed by decree 2026-04-01). That mattered: Rust sorted with a stable
/// sort and the C mirror used `qsort` (not stable), so two implementations
/// could order equal-key entries differently and produce different bytes for
/// the same transaction. Comparing the value as a tiebreaker removes the
/// ambiguity, so both languages agree without depending on sort stability.
pub fn canonical_cmp(a: &MetadataEntry, b: &MetadataEntry) -> std::cmp::Ordering {
    a.key.cmp(&b.key).then_with(|| a.value.cmp(&b.value))
}

/// Whether `entries` are in canonical order (ascending by key, then value).
pub fn is_canonical_order(entries: &[MetadataEntry]) -> bool {
    entries
        .windows(2)
        .all(|w| canonical_cmp(&w[0], &w[1]) != std::cmp::Ordering::Greater)
}

/// Sort `entries` into canonical order. Builders should call this before
/// signing so the transaction they produce is accepted.
pub fn sort_canonical(entries: &mut [MetadataEntry]) {
    entries.sort_by(canonical_cmp);
}

/// Validate a list of metadata entries: individual bounds (T8) and canonical
/// ordering (T9b).
///
/// Duplicate keys are allowed (T9 removed by decree 2026-04-01), which is
/// exactly why order has to be pinned. Protocol readers take the **first**
/// match for a key — `doc:prev_checksum`, `doc:version`, and the `locked:*`
/// decryption inputs all use `.iter().find(...)` — while the signing payload
/// sorted metadata and the wire encoding did not. An attacker could therefore
/// reorder duplicate entries in transit, leave the signature verifying, and
/// change which value the node acts on. Requiring canonical order on the wire
/// makes any reordered copy invalid rather than silently meaningful.
pub fn validate_metadata(entries: &[MetadataEntry]) -> Result<(), ValidationError> {
    for entry in entries {
        entry.validate()?;
    }
    if !is_canonical_order(entries) {
        return Err(ValidationError::MetadataNotCanonical);
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
    fn duplicate_keys_accepted() {
        // T9 removed by decree (2026-04-01): duplicate metadata keys are allowed.
        let entries = vec![
            MetadataEntry {
                key: "doc:url".into(),
                value: b"https://example.com/a.pdf".to_vec(),
            },
            MetadataEntry {
                key: "doc:url".into(),
                value: b"https://mirror.example.com/a.pdf".to_vec(),
            },
        ];
        assert!(validate_metadata(&entries).is_ok());
    }

    // --- T9b: canonical metadata ordering ---

    fn entry(key: &str, value: &[u8]) -> MetadataEntry {
        MetadataEntry { key: key.into(), value: value.to_vec() }
    }

    #[test]
    fn reordered_duplicate_keys_are_rejected() {
        // The mutation this rule exists to stop: two entries share a key, and
        // protocol readers take the FIRST match. Swapping them changes which
        // value the node acts on while the signature still verifies, because
        // the signing payload sorts metadata but the wire encoding does not.
        let canonical = vec![
            entry("doc:url", b"https://a.example/a.pdf"),
            entry("doc:url", b"https://b.example/a.pdf"),
        ];
        assert!(validate_metadata(&canonical).is_ok());

        let swapped = vec![canonical[1].clone(), canonical[0].clone()];
        assert!(
            matches!(validate_metadata(&swapped), Err(ValidationError::MetadataNotCanonical)),
            "a reordered copy must be invalid, not silently meaningful"
        );
    }

    #[test]
    fn locked_field_reordering_is_rejected() {
        // `locked:*` entries are decryption inputs read by first match, so a
        // reordering here changes what the node decrypts.
        let swapped = vec![
            entry("locked:salt", b"second-salt"),
            entry("locked:salt", b"first-salt"),
        ];
        assert!(matches!(
            validate_metadata(&swapped),
            Err(ValidationError::MetadataNotCanonical)
        ));
    }

    #[test]
    fn keys_out_of_order_are_rejected() {
        let entries = vec![entry("doc:version", b"2"), entry("doc:prev_checksum", b"ab")];
        assert!(matches!(
            validate_metadata(&entries),
            Err(ValidationError::MetadataNotCanonical)
        ));
    }

    #[test]
    fn sort_canonical_makes_any_order_valid() {
        let mut entries = vec![
            entry("doc:url", b"zzz"),
            entry("doc:prev_checksum", b"ab"),
            entry("doc:url", b"aaa"),
        ];
        assert!(validate_metadata(&entries).is_err());
        sort_canonical(&mut entries);
        assert!(validate_metadata(&entries).is_ok());
        // Equal keys are ordered by value, giving one deterministic result.
        assert_eq!(entries[1].value, b"aaa".to_vec());
        assert_eq!(entries[2].value, b"zzz".to_vec());
    }

    #[test]
    fn canonical_cmp_is_a_total_order_over_equal_keys() {
        // Key-only comparison would call these equal, leaving their relative
        // order down to sort stability — which Rust and the C mirror do not
        // share. The value tiebreaker removes the ambiguity.
        let a = entry("k", b"1");
        let b = entry("k", b"2");
        assert_eq!(canonical_cmp(&a, &b), std::cmp::Ordering::Less);
        assert_eq!(canonical_cmp(&b, &a), std::cmp::Ordering::Greater);
        assert_eq!(canonical_cmp(&a, &a.clone()), std::cmp::Ordering::Equal);
    }

    #[test]
    fn empty_and_single_entry_are_trivially_canonical() {
        assert!(validate_metadata(&[]).is_ok());
        assert!(validate_metadata(&[entry("k", b"v")]).is_ok());
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
