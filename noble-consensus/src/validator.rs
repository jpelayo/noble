// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Validator list management with CBOR persistence.

use std::collections::HashMap;

use noble_crypto::NoblePublicKey;
use serde::{Deserialize, Serialize};

/// A single validator entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorEntry {
    pubkey: NoblePublicKey,
    weight: u64,
}

/// Manages the set of trusted validators for the consensus engine.
///
/// Keyed by wire-format public key bytes for fast lookup.
/// Supports CBOR serialization for persistent storage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorList {
    /// wire_bytes → (pubkey, weight)
    entries: HashMap<Vec<u8>, ValidatorEntry>,
}

impl ValidatorList {
    /// Create an empty validator list.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Check if a public key is in the validator list.
    pub fn is_validator(&self, pubkey: &NoblePublicKey) -> bool {
        self.entries.contains_key(&pubkey.to_wire_bytes())
    }

    /// Add a validator with the given weight.
    /// If already present, updates the weight.
    pub fn add_validator(&mut self, pubkey: NoblePublicKey, weight: u64) {
        let wire = pubkey.to_wire_bytes();
        self.entries.insert(wire, ValidatorEntry { pubkey, weight });
    }

    /// Remove a validator. Returns `true` if it was present.
    pub fn remove_validator(&mut self, pubkey: &NoblePublicKey) -> bool {
        self.entries.remove(&pubkey.to_wire_bytes()).is_some()
    }

    /// List all validators sorted by weight (descending), then by wire bytes (ascending) for determinism.
    pub fn list_validators(&self) -> Vec<(NoblePublicKey, u64)> {
        let mut list: Vec<_> = self
            .entries
            .iter()
            .map(|(wire, entry)| (wire.clone(), entry.pubkey.clone(), entry.weight))
            .collect();
        list.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        list.into_iter().map(|(_, pk, w)| (pk, w)).collect()
    }

    /// Return the list as a flat slice of public keys (for `BlockValidationContext`).
    pub fn as_pubkey_vec(&self) -> Vec<NoblePublicKey> {
        self.list_validators()
            .into_iter()
            .map(|(pk, _)| pk)
            .collect()
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{ed25519, NoblePrivateKey};

    fn make_pubkey() -> NoblePublicKey {
        let (sk, _) = ed25519::generate_keypair();
        NoblePrivateKey::Ed25519(sk).public_key()
    }

    #[test]
    fn empty_list() {
        let list = ValidatorList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(!list.is_validator(&make_pubkey()));
    }

    #[test]
    fn add_and_check_validator() {
        let mut list = ValidatorList::new();
        let pk = make_pubkey();
        list.add_validator(pk.clone(), 100);
        assert!(list.is_validator(&pk));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn remove_validator() {
        let mut list = ValidatorList::new();
        let pk = make_pubkey();
        list.add_validator(pk.clone(), 100);
        assert!(list.remove_validator(&pk));
        assert!(!list.is_validator(&pk));
        assert!(list.is_empty());
        // Removing again returns false
        assert!(!list.remove_validator(&pk));
    }

    #[test]
    fn list_sorted_by_weight_desc() {
        let mut list = ValidatorList::new();
        let pk_low = make_pubkey();
        let pk_high = make_pubkey();
        let pk_mid = make_pubkey();
        list.add_validator(pk_low.clone(), 10);
        list.add_validator(pk_high.clone(), 100);
        list.add_validator(pk_mid.clone(), 50);

        let sorted = list.list_validators();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].1, 100);
        assert_eq!(sorted[1].1, 50);
        assert_eq!(sorted[2].1, 10);
    }

    #[test]
    fn cbor_roundtrip() {
        use noble_codec::NobleCbor;

        let mut list = ValidatorList::new();
        list.add_validator(make_pubkey(), 100);
        list.add_validator(make_pubkey(), 50);

        let bytes = list.to_cbor().unwrap();
        let decoded = ValidatorList::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
    }
}
