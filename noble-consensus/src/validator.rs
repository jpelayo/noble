// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Validator list management with CBOR persistence.

use std::collections::HashMap;

use noble_crypto::NoblePublicKey;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Validator liveness status, derived from `last_seen` relative to thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorLiveness {
    /// Last seen within `VALIDATOR_ALIVE_THRESHOLD_SECS` (3 cycles).
    Alive,
    /// Last seen between alive and stale thresholds.
    Stale,
    /// Last seen beyond `VALIDATOR_STALE_THRESHOLD_SECS` (12 cycles), or never seen.
    Unreachable,
}

impl ValidatorLiveness {
    /// Compute liveness from a `last_seen` timestamp and the current time.
    pub fn from_last_seen(last_seen: Option<u64>, now: u64) -> Self {
        match last_seen {
            None => Self::Unreachable,
            Some(ts) => {
                let age = now.saturating_sub(ts);
                if age <= noble_core::VALIDATOR_ALIVE_THRESHOLD_SECS {
                    Self::Alive
                } else if age <= noble_core::VALIDATOR_STALE_THRESHOLD_SECS {
                    Self::Stale
                } else {
                    Self::Unreachable
                }
            }
        }
    }

    /// String label for API/GUI display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Stale => "stale",
            Self::Unreachable => "unreachable",
        }
    }
}

/// Tuple returned by `list_validators_with_liveness()`:
/// (pubkey, weight, liveness, added_at, friendly_name)
pub type ValidatorWithLiveness = (
    NoblePublicKey,
    u64,
    ValidatorLiveness,
    Option<u64>,
    Option<String>,
);

/// A single validator entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pubkey: NoblePublicKey,
    weight: u64,
    /// Last seen timestamp from peer memory (updated externally).
    #[serde(default)]
    last_seen: Option<u64>,
    /// When the operator added this validator (unix timestamp).
    #[serde(default)]
    added_at: Option<u64>,
    /// Operator-given friendly name.
    #[serde(default)]
    friendly_name: Option<String>,
}

/// A pending key rotation that is within the grace period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRotation {
    /// The old key being rotated away.
    pub old_key: NoblePublicKey,
    /// The new key replacing it.
    pub new_key: NoblePublicKey,
    /// The cycle at which the rotation was submitted.
    pub rotation_cycle: u64,
}

/// Manages the set of trusted validators for the consensus engine.
///
/// Keyed by wire-format public key bytes for fast lookup.
/// Supports CBOR serialization for persistent storage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorList {
    /// wire_bytes → (pubkey, weight)
    entries: HashMap<Vec<u8>, ValidatorEntry>,
    /// Pending key rotations: old_key_wire → PendingRotation
    pending_rotations: HashMap<Vec<u8>, PendingRotation>,
}

impl ValidatorList {
    /// Create an empty validator list.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            pending_rotations: HashMap::new(),
        }
    }

    /// Check if a public key is in the validator list.
    pub fn is_validator(&self, pubkey: &NoblePublicKey) -> bool {
        self.entries.contains_key(&pubkey.to_wire_bytes())
    }

    /// Add a validator with the given weight.
    /// If already present, updates the weight.
    /// `now` is the current unix timestamp in seconds.
    pub fn add_validator(&mut self, pubkey: NoblePublicKey, weight: u64, now: u64) {
        debug!("validator added: {:?}", pubkey);
        let wire = pubkey.to_wire_bytes();
        self.entries.insert(
            wire,
            ValidatorEntry {
                pubkey,
                weight,
                last_seen: None,
                added_at: Some(now),
                friendly_name: None,
            },
        );
    }

    /// Update the `last_seen` timestamp for a validator (from peer memory).
    pub fn update_last_seen(&mut self, pubkey: &NoblePublicKey, last_seen: u64) {
        if let Some(entry) = self.entries.get_mut(&pubkey.to_wire_bytes()) {
            entry.last_seen = Some(last_seen);
        }
    }

    /// Set a friendly name for a validator.
    pub fn set_friendly_name(&mut self, pubkey: &NoblePublicKey, name: String) {
        if let Some(entry) = self.entries.get_mut(&pubkey.to_wire_bytes()) {
            entry.friendly_name = Some(name);
        }
    }

    /// Get liveness status for a specific validator.
    pub fn validator_liveness(&self, pubkey: &NoblePublicKey, now: u64) -> ValidatorLiveness {
        self.entries
            .get(&pubkey.to_wire_bytes())
            .map(|e| ValidatorLiveness::from_last_seen(e.last_seen, now))
            .unwrap_or(ValidatorLiveness::Unreachable)
    }

    /// List validators with their liveness and metadata.
    pub fn list_validators_with_liveness(&self, now: u64) -> Vec<ValidatorWithLiveness> {
        let mut list: Vec<_> = self
            .entries
            .iter()
            .map(|(wire, entry)| {
                let liveness = ValidatorLiveness::from_last_seen(entry.last_seen, now);
                (
                    wire.clone(),
                    entry.pubkey.clone(),
                    entry.weight,
                    liveness,
                    entry.added_at,
                    entry.friendly_name.clone(),
                )
            })
            .collect();
        list.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        list.into_iter()
            .map(|(_, pk, w, lv, added, name)| (pk, w, lv, added, name))
            .collect()
    }

    /// Remove a validator. Returns `true` if it was present.
    pub fn remove_validator(&mut self, pubkey: &NoblePublicKey) -> bool {
        let removed = self.entries.remove(&pubkey.to_wire_bytes()).is_some();
        if removed {
            debug!("validator removed: {:?}", pubkey);
        }
        removed
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

    /// Schedule a key rotation with a grace period.
    ///
    /// During the grace period (`rotation_cycle..rotation_cycle + grace_cycles`),
    /// both old and new keys are accepted. After the grace period, only the new key
    /// is valid and the old key is removed.
    ///
    /// Returns `Err(reason)` if:
    /// - `old_key` is not a current validator (T18)
    /// - `old_key` already has a pending rotation (T20)
    pub fn apply_rotation(
        &mut self,
        old_key: &NoblePublicKey,
        new_key: NoblePublicKey,
        current_cycle: u64,
    ) -> Result<(), String> {
        let old_wire = old_key.to_wire_bytes();

        // T18: Must be a current validator
        if !self.entries.contains_key(&old_wire) {
            return Err("signer is not a current validator".to_string());
        }

        // T20: No duplicate rotation within grace period
        if self.pending_rotations.contains_key(&old_wire) {
            return Err(format!(
                "key rotation already pending (submitted at cycle {})",
                self.pending_rotations[&old_wire].rotation_cycle
            ));
        }

        self.pending_rotations.insert(
            old_wire,
            PendingRotation {
                old_key: old_key.clone(),
                new_key,
                rotation_cycle: current_cycle,
            },
        );

        Ok(())
    }

    /// Check if a public key is a valid validator, considering pending rotations.
    ///
    /// During a grace period, both the old and new key are accepted.
    /// After the grace period, only the new key is valid.
    pub fn is_valid_validator_key(
        &self,
        pubkey: &NoblePublicKey,
        current_cycle: u64,
        grace_cycles: u64,
    ) -> bool {
        let wire = pubkey.to_wire_bytes();

        // Direct match — key is in the active validator set
        if self.entries.contains_key(&wire) {
            return true;
        }

        // Check if the key is a new key within a pending rotation's grace period
        for rotation in self.pending_rotations.values() {
            if rotation.new_key == *pubkey && current_cycle < rotation.rotation_cycle + grace_cycles
            {
                return true;
            }
        }

        false
    }

    /// Finalize rotations whose grace period has expired.
    ///
    /// For each expired rotation: removes the old key, inserts the new key
    /// with the same weight. Returns the list of finalized rotations.
    pub fn finalize_rotations(
        &mut self,
        current_cycle: u64,
        grace_cycles: u64,
    ) -> Vec<PendingRotation> {
        let expired: Vec<Vec<u8>> = self
            .pending_rotations
            .iter()
            .filter(|(_, r)| current_cycle >= r.rotation_cycle + grace_cycles)
            .map(|(wire, _)| wire.clone())
            .collect();

        let mut finalized = Vec::new();
        for old_wire in expired {
            if let Some(rotation) = self.pending_rotations.remove(&old_wire) {
                // Preserve metadata from old key
                let old_entry = self.entries.remove(&old_wire);
                let weight = old_entry.as_ref().map(|e| e.weight).unwrap_or(100);
                let added_at = old_entry.as_ref().and_then(|e| e.added_at);
                let friendly_name = old_entry.and_then(|e| e.friendly_name);
                let new_wire = rotation.new_key.to_wire_bytes();
                self.entries.insert(
                    new_wire,
                    ValidatorEntry {
                        pubkey: rotation.new_key.clone(),
                        weight,
                        last_seen: None,
                        added_at,
                        friendly_name,
                    },
                );
                finalized.push(rotation);
            }
        }

        finalized
    }

    /// Get all pending rotations (for persistence).
    pub fn pending_rotations(&self) -> &HashMap<Vec<u8>, PendingRotation> {
        &self.pending_rotations
    }

    /// Load pending rotations from storage (called at startup).
    pub fn load_pending_rotations(&mut self, rotations: Vec<PendingRotation>) {
        for r in rotations {
            let old_wire = r.old_key.to_wire_bytes();
            self.pending_rotations.insert(old_wire, r);
        }
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
        list.add_validator(pk.clone(), 100, 1_700_000_000);
        assert!(list.is_validator(&pk));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn remove_validator() {
        let mut list = ValidatorList::new();
        let pk = make_pubkey();
        list.add_validator(pk.clone(), 100, 1_700_000_000);
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
        list.add_validator(pk_low.clone(), 10, 1_700_000_000);
        list.add_validator(pk_high.clone(), 100, 1_700_000_000);
        list.add_validator(pk_mid.clone(), 50, 1_700_000_000);

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
        list.add_validator(make_pubkey(), 100, 1_700_000_000);
        list.add_validator(make_pubkey(), 50, 1_700_000_000);

        let bytes = list.to_cbor().unwrap();
        let decoded = ValidatorList::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
    }

    // --- Key rotation tests ---

    #[test]
    fn apply_rotation_valid() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);

        assert!(list.apply_rotation(&old_key, new_key.clone(), 10).is_ok());
        assert_eq!(list.pending_rotations().len(), 1);
    }

    #[test]
    fn apply_rotation_non_validator_rejected() {
        let mut list = ValidatorList::new();
        let non_validator = make_pubkey();
        let new_key = make_pubkey();

        let result = list.apply_rotation(&non_validator, new_key, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a current validator"));
    }

    #[test]
    fn apply_rotation_duplicate_rejected() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key1 = make_pubkey();
        let new_key2 = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);

        assert!(list.apply_rotation(&old_key, new_key1, 10).is_ok());
        let result = list.apply_rotation(&old_key, new_key2, 11);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already pending"));
    }

    #[test]
    fn old_key_valid_during_grace_period() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);
        list.apply_rotation(&old_key, new_key.clone(), 10).unwrap();

        // During grace period (cycle 10, grace=48, so valid until cycle 58)
        assert!(list.is_valid_validator_key(&old_key, 30, 48));
    }

    #[test]
    fn new_key_valid_during_grace_period() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);
        list.apply_rotation(&old_key, new_key.clone(), 10).unwrap();

        // New key should be valid during grace period
        assert!(list.is_valid_validator_key(&new_key, 30, 48));
    }

    #[test]
    fn finalize_rotation_swaps_keys() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);
        list.apply_rotation(&old_key, new_key.clone(), 10).unwrap();

        // Finalize at cycle 58 (10 + 48 = 58, grace expired)
        let finalized = list.finalize_rotations(58, 48);
        assert_eq!(finalized.len(), 1);

        // Old key removed, new key added
        assert!(!list.is_validator(&old_key));
        assert!(list.is_validator(&new_key));
        assert_eq!(list.len(), 1); // same count
        assert!(list.pending_rotations().is_empty());
    }

    #[test]
    fn finalize_rotation_preserves_weight() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 75, 1_700_000_000);
        list.apply_rotation(&old_key, new_key.clone(), 10).unwrap();

        list.finalize_rotations(58, 48);

        let validators = list.list_validators();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].0, new_key);
        assert_eq!(validators[0].1, 75);
    }

    #[test]
    fn load_pending_rotations() {
        let mut list = ValidatorList::new();
        let old_key = make_pubkey();
        let new_key = make_pubkey();
        list.add_validator(old_key.clone(), 100, 1_700_000_000);

        let rotation = PendingRotation {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            rotation_cycle: 5,
        };
        list.load_pending_rotations(vec![rotation]);

        assert_eq!(list.pending_rotations().len(), 1);
        assert!(list.is_valid_validator_key(&new_key, 10, 48));
    }

    // ── Liveness Tests ──

    #[test]
    fn validator_alive_within_threshold() {
        let now = 1_700_000_000;
        let liveness = ValidatorLiveness::from_last_seen(Some(now - 1000), now);
        assert_eq!(liveness, ValidatorLiveness::Alive);
    }

    #[test]
    fn validator_stale_beyond_alive_threshold() {
        let now = 1_700_000_000;
        // 10,000s > 5,400 (alive) but < 21,600 (stale)
        let liveness = ValidatorLiveness::from_last_seen(Some(now - 10_000), now);
        assert_eq!(liveness, ValidatorLiveness::Stale);
    }

    #[test]
    fn validator_unreachable_beyond_stale_threshold() {
        let now = 1_700_000_000;
        let liveness = ValidatorLiveness::from_last_seen(Some(now - 30_000), now);
        assert_eq!(liveness, ValidatorLiveness::Unreachable);
    }

    #[test]
    fn validator_unreachable_when_never_seen() {
        let now = 1_700_000_000;
        let liveness = ValidatorLiveness::from_last_seen(None, now);
        assert_eq!(liveness, ValidatorLiveness::Unreachable);
    }

    #[test]
    fn update_last_seen_changes_liveness() {
        let mut list = ValidatorList::new();
        let pk = make_pubkey();
        list.add_validator(pk.clone(), 100, 1_700_000_000);

        let now = 1_700_000_000;
        // Before update: no last_seen → unreachable
        assert_eq!(
            list.validator_liveness(&pk, now),
            ValidatorLiveness::Unreachable
        );

        // After update with recent timestamp → alive
        list.update_last_seen(&pk, now - 100);
        assert_eq!(list.validator_liveness(&pk, now), ValidatorLiveness::Alive);
    }

    #[test]
    fn list_validators_with_liveness_includes_metadata() {
        let mut list = ValidatorList::new();
        let pk = make_pubkey();
        list.add_validator(pk.clone(), 100, 1_700_000_000);
        list.set_friendly_name(&pk, "test-validator".to_string());
        list.update_last_seen(&pk, 1_700_000_000);

        let now = 1_700_000_000 + 100;
        let result = list.list_validators_with_liveness(now);
        assert_eq!(result.len(), 1);
        let (_, weight, liveness, added_at, name) = &result[0];
        assert_eq!(*weight, 100);
        assert_eq!(*liveness, ValidatorLiveness::Alive);
        assert!(added_at.is_some());
        assert_eq!(name.as_deref(), Some("test-validator"));
    }
}
