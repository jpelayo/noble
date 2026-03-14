// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! ValidatorRegistry — centralized wrapper around ValidatorList with
//! dirty-flag persistence, snapshot creation, and CBOR V1/V2 support.
//!
//! Phase 1 of the ValidatorRegistry architectural promotion.  At this stage
//! the registry wraps `ValidatorList` internally and delegates all methods.
//! External callers can be gradually migrated from `CycleEngine.validator_list()`
//! to `ValidatorRegistry` on its own `Arc<RwLock<>>`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use noble_crypto::NoblePublicKey;

use crate::validator::{
    KnownPeerEntry, PendingRotation, ValidatorEntry, ValidatorList, ValidatorLiveness,
    ValidatorWithLiveness,
};

/// Source of how a participant was registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ParticipantSource {
    /// Self-registration or operator `addValidator` RPC.
    Local,
    /// Auto-registered from NodeAnnounce.
    Discovered,
    /// Discovered then confirmed by operator.
    Confirmed,
}

/// A unified participant entry merging the old `ValidatorEntry` and `KnownPeerEntry` models.
///
/// Single map: `participants: HashMap<Vec<u8>, ParticipantEntry>` keyed by wire bytes.
/// All validators are participants with `wants_to_validate == true`.
/// Known-peers-only entries have `wants_to_validate == false`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParticipantEntry {
    pub pubkey: NoblePublicKey,
    /// Whether this participant wants to be a block proposer.
    pub wants_to_validate: bool,
    /// Whether this participant wants to vote on blocks.
    pub wants_to_vote: bool,
    /// Validator weight (meaningful only when `wants_to_validate`).
    pub weight: u64,
    /// Operator-given or NodeAnnounce-derived friendly name.
    pub node_name: Option<String>,
    /// Host address / multiaddr (from NodeAnnounce).
    pub host_address: Option<String>,
    /// ISO 3166-1 alpha-3 country code (from NodeAnnounce).
    pub country_code: Option<String>,
    /// Organization type string (from NodeAnnounce).
    pub org_type: Option<String>,
    /// Node role string (from NodeAnnounce).
    pub node_role: Option<String>,
    /// Hex-encoded libp2p PeerId bytes (from NodeAnnounce).
    pub peer_id_hex: Option<String>,
    /// Last seen timestamp (transient, not persisted).
    #[serde(default)]
    pub last_seen: Option<u64>,
    /// First discovery timestamp.
    pub first_seen: Option<u64>,
    /// When the operator added this validator (unix timestamp).
    pub added_at: Option<u64>,
    /// How this entry was created.
    pub source: ParticipantSource,
}

impl ParticipantEntry {
    /// Friendly name for this participant, falling back to empty string.
    pub fn name(&self) -> String {
        self.node_name.clone().unwrap_or_default()
    }
}

/// A lock-free, immutable snapshot of the validator set.
///
/// Created once per tick from `ValidatorRegistry.create_snapshot()`,
/// then passed to the consensus engine — no lock held during processing.
#[derive(Debug, Clone)]
pub struct ValidatorSnapshot {
    /// Wire bytes → (pubkey, weight, name) for quick lookup.
    pub entries: Vec<(Vec<u8>, SnapshotEntry)>,
    /// Priority-ordered wire keys for voting strategies.
    pub ordered_keys: Vec<Vec<u8>>,
    /// Flat pubkey list for `BlockValidationContext`.
    pub pubkey_vec: Vec<NoblePublicKey>,
    /// Total validator count.
    pub count: usize,
}

/// Single entry within a snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub pubkey: NoblePublicKey,
    pub weight: u64,
    pub name: String,
}

impl ValidatorSnapshot {
    /// Look up a validator by wire bytes in the snapshot.
    pub fn find_by_wire(&self, wire: &[u8]) -> Option<&SnapshotEntry> {
        self.entries
            .iter()
            .find(|(w, _)| w.as_slice() == wire)
            .map(|(_, e)| e)
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up the weight of a validator by wire bytes.
    pub fn weight_of_wire(&self, wire: &[u8]) -> Option<u64> {
        self.find_by_wire(wire).map(|e| e.weight)
    }

    /// Return validator wire-key bytes in operator-defined priority order.
    pub fn ordered_validator_keys(&self) -> &[Vec<u8>] {
        &self.ordered_keys
    }

    /// Return the list as a flat slice of public keys (for `BlockValidationContext`).
    pub fn as_pubkey_vec(&self) -> &[NoblePublicKey] {
        &self.pubkey_vec
    }
}

/// Centralized wrapper around `ValidatorList` with dirty-flag persistence
/// and snapshot creation.
///
/// In the final architecture (Phase 5+), this will replace ValidatorList
/// entirely with a unified `ParticipantEntry` map.  For now it delegates
/// to the inner `ValidatorList`.
pub struct ValidatorRegistry {
    inner: ValidatorList,
    persistence_path: Option<PathBuf>,
    dirty: bool,
}

impl ValidatorRegistry {
    /// Create a new registry wrapping the given `ValidatorList`.
    pub fn new(validator_list: ValidatorList, persistence_path: Option<PathBuf>) -> Self {
        Self {
            inner: validator_list,
            persistence_path,
            dirty: false,
        }
    }

    /// Create an empty registry (no persistence).
    pub fn empty() -> Self {
        Self {
            inner: ValidatorList::new(),
            persistence_path: None,
            dirty: false,
        }
    }

    /// Mark the registry as dirty (needs persistence).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Whether the registry has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Persist to disk if dirty. Returns `Ok(true)` if written, `Ok(false)` if clean.
    pub fn persist_if_dirty(&mut self) -> Result<bool, String> {
        if !self.dirty {
            return Ok(false);
        }
        self.persist()?;
        self.dirty = false;
        Ok(true)
    }

    /// Force-persist regardless of dirty flag.
    pub fn persist(&self) -> Result<(), String> {
        if let Some(ref path) = self.persistence_path {
            let bytes = noble_codec::NobleCbor::to_cbor(&self.inner)
                .map_err(|e| format!("serialize validator list: {e}"))?;
            std::fs::write(path, &bytes)
                .map_err(|e| format!("persist validator list: {e}"))?;
        }
        Ok(())
    }

    /// Create an immutable snapshot for lock-free consensus processing.
    pub fn create_snapshot(&self) -> Arc<ValidatorSnapshot> {
        let entries: Vec<(Vec<u8>, SnapshotEntry)> = self
            .inner
            .list_validators()
            .into_iter()
            .map(|(pk, weight)| {
                let wire = pk.to_wire_bytes();
                let name = self
                    .inner
                    .find_by_wire(&wire)
                    .map(|v| v.name())
                    .unwrap_or_default();
                (
                    wire,
                    SnapshotEntry {
                        pubkey: pk,
                        weight,
                        name,
                    },
                )
            })
            .collect();
        let ordered_keys = self.inner.ordered_validator_keys();
        let pubkey_vec = entries.iter().map(|(_, e)| e.pubkey.clone()).collect();
        let count = entries.len();
        Arc::new(ValidatorSnapshot {
            entries,
            ordered_keys,
            pubkey_vec,
            count,
        })
    }

    /// Get a reference to the inner `ValidatorList` (for callers still using it directly).
    pub fn inner(&self) -> &ValidatorList {
        &self.inner
    }

    /// Get a mutable reference to the inner `ValidatorList`.
    pub fn inner_mut(&mut self) -> &mut ValidatorList {
        &mut self.inner
    }

    /// Consume the registry and return the inner `ValidatorList`.
    pub fn into_inner(self) -> ValidatorList {
        self.inner
    }

    /// Get a clone of the inner `ValidatorList` (for backward compat with CycleEngine).
    pub fn clone_inner(&self) -> ValidatorList {
        self.inner.clone()
    }

    // ── Delegated methods (write operations mark dirty) ──

    /// Check if a public key is in the validator list.
    pub fn is_validator(&self, pubkey: &NoblePublicKey) -> bool {
        self.inner.is_validator(pubkey)
    }

    /// Look up a validator by wire bytes.
    pub fn find_by_wire(&self, wire: &[u8]) -> Option<&ValidatorEntry> {
        self.inner.find_by_wire(wire)
    }

    /// Add a validator with the given weight.
    pub fn add_validator(&mut self, pubkey: NoblePublicKey, weight: u64, now: u64) {
        self.inner.add_validator(pubkey, weight, now);
        self.dirty = true;
    }

    /// Update the `last_seen` timestamp for a validator.
    pub fn update_last_seen(&mut self, pubkey: &NoblePublicKey, last_seen: u64) {
        self.inner.update_last_seen(pubkey, last_seen);
        // last_seen updates are frequent and transient — don't mark dirty
    }

    /// Update network metadata for a validator.
    pub fn update_network_info(
        &mut self,
        pubkey: &NoblePublicKey,
        host_address: Option<String>,
        country_code: Option<String>,
    ) {
        self.inner.update_network_info(pubkey, host_address, country_code);
        self.dirty = true;
    }

    /// Get all validator host addresses.
    pub fn validator_addresses(&self) -> Vec<String> {
        self.inner.validator_addresses()
    }

    /// Update or insert a known peer from NodeAnnounce data.
    pub fn update_known_peer(
        &mut self,
        identity_key_hex: &str,
        node_name: Option<String>,
        host_address: Option<String>,
        country_code: Option<String>,
        wants_to_validate: bool,
        wants_to_vote: bool,
        org_type: Option<String>,
        node_role: Option<String>,
        peer_id_hex: Option<String>,
        now: u64,
    ) {
        self.inner.update_known_peer(
            identity_key_hex,
            node_name,
            host_address,
            country_code,
            wants_to_validate,
            wants_to_vote,
            org_type,
            node_role,
            peer_id_hex,
            now,
        );
        self.dirty = true;
    }

    /// Remove a known peer by identity key hex.
    pub fn remove_known_peer(&mut self, identity_key_hex: &str) -> bool {
        let removed = self.inner.remove_known_peer(identity_key_hex);
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Get all known peers.
    pub fn known_peers(&self) -> &HashMap<String, KnownPeerEntry> {
        self.inner.known_peers()
    }

    /// Remove all discovered peers.
    pub fn clear_known_peers(&mut self) {
        self.inner.clear_known_peers();
        self.dirty = true;
    }

    /// Get all known peer host addresses.
    pub fn known_peer_addresses(&self) -> Vec<String> {
        self.inner.known_peer_addresses()
    }

    /// Set a friendly name for a validator.
    pub fn set_friendly_name(&mut self, pubkey: &NoblePublicKey, name: String) {
        self.inner.set_friendly_name(pubkey, name);
        self.dirty = true;
    }

    /// Get liveness status for a specific validator.
    pub fn validator_liveness(&self, pubkey: &NoblePublicKey, now: u64) -> ValidatorLiveness {
        self.inner.validator_liveness(pubkey, now)
    }

    /// List validators with their liveness and metadata.
    pub fn list_validators_with_liveness(&self, now: u64) -> Vec<ValidatorWithLiveness> {
        self.inner.list_validators_with_liveness(now)
    }

    /// Remove a validator. Returns `true` if it was present.
    pub fn remove_validator(&mut self, pubkey: &NoblePublicKey) -> bool {
        let removed = self.inner.remove_validator(pubkey);
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// List all validators sorted by weight.
    pub fn list_validators(&self) -> Vec<(NoblePublicKey, u64)> {
        self.inner.list_validators()
    }

    /// Return the list as a flat slice of public keys.
    pub fn as_pubkey_vec(&self) -> Vec<NoblePublicKey> {
        self.inner.as_pubkey_vec()
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return validator wire-key bytes sorted lexicographically.
    pub fn sorted_validator_keys(&self) -> Vec<Vec<u8>> {
        self.inner.sorted_validator_keys()
    }

    /// Return validator wire-key bytes in operator-defined priority order.
    pub fn ordered_validator_keys(&self) -> Vec<Vec<u8>> {
        self.inner.ordered_validator_keys()
    }

    /// Get the operator-defined priority order.
    pub fn priority_order(&self) -> &[Vec<u8>] {
        self.inner.priority_order()
    }

    /// Set the operator-defined priority order.
    pub fn set_priority_order(&mut self, order: Vec<Vec<u8>>) -> Result<(), String> {
        self.inner.set_priority_order(order)?;
        self.dirty = true;
        Ok(())
    }

    /// Look up the weight of a validator by its wire-format key bytes.
    pub fn weight_of_wire(&self, wire_bytes: &[u8]) -> Option<u64> {
        self.inner.weight_of_wire(wire_bytes)
    }

    /// Schedule a key rotation with a grace period.
    pub fn apply_rotation(
        &mut self,
        old_key: &NoblePublicKey,
        new_key: NoblePublicKey,
        current_cycle: u64,
    ) -> Result<(), String> {
        self.inner.apply_rotation(old_key, new_key, current_cycle)?;
        self.dirty = true;
        Ok(())
    }

    /// Check if a public key is a valid validator, considering pending rotations.
    pub fn is_valid_validator_key(
        &self,
        pubkey: &NoblePublicKey,
        current_cycle: u64,
        grace_cycles: u64,
    ) -> bool {
        self.inner.is_valid_validator_key(pubkey, current_cycle, grace_cycles)
    }

    /// Finalize rotations whose grace period has expired.
    pub fn finalize_rotations(
        &mut self,
        current_cycle: u64,
        grace_cycles: u64,
    ) -> Vec<PendingRotation> {
        let finalized = self.inner.finalize_rotations(current_cycle, grace_cycles);
        if !finalized.is_empty() {
            self.dirty = true;
        }
        finalized
    }

    /// Get all pending rotations.
    pub fn pending_rotations(&self) -> &HashMap<Vec<u8>, PendingRotation> {
        self.inner.pending_rotations()
    }

    /// Load pending rotations from storage.
    pub fn load_pending_rotations(&mut self, rotations: Vec<PendingRotation>) {
        self.inner.load_pending_rotations(rotations);
    }

    /// Load from CBOR bytes (V1 format — existing ValidatorList).
    pub fn from_cbor_with_path(
        bytes: &[u8],
        persistence_path: Option<PathBuf>,
    ) -> Result<Self, String> {
        let inner = noble_codec::NobleCbor::from_cbor(bytes)
            .map_err(|e| format!("deserialize validator list: {e}"))?;
        Ok(Self {
            inner,
            persistence_path,
            dirty: false,
        })
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
    fn registry_delegates_add_and_check() {
        let mut reg = ValidatorRegistry::empty();
        let pk = make_pubkey();
        assert!(!reg.is_dirty());

        reg.add_validator(pk.clone(), 100, 1_700_000_000);
        assert!(reg.is_validator(&pk));
        assert_eq!(reg.len(), 1);
        assert!(reg.is_dirty());
    }

    #[test]
    fn registry_remove_marks_dirty() {
        let mut reg = ValidatorRegistry::empty();
        let pk = make_pubkey();
        reg.add_validator(pk.clone(), 100, 1_700_000_000);
        reg.dirty = false; // reset

        assert!(reg.remove_validator(&pk));
        assert!(reg.is_dirty());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_update_last_seen_does_not_mark_dirty() {
        let mut reg = ValidatorRegistry::empty();
        let pk = make_pubkey();
        reg.add_validator(pk.clone(), 100, 1_700_000_000);
        reg.dirty = false;

        reg.update_last_seen(&pk, 1_700_001_000);
        assert!(!reg.is_dirty());
    }

    #[test]
    fn snapshot_creation() {
        let mut reg = ValidatorRegistry::empty();
        let pk1 = make_pubkey();
        let pk2 = make_pubkey();
        reg.add_validator(pk1.clone(), 100, 1_700_000_000);
        reg.add_validator(pk2.clone(), 50, 1_700_000_000);
        reg.set_friendly_name(&pk1, "node-alpha".to_string());

        let snap = reg.create_snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.pubkey_vec.len(), 2);
        assert_eq!(snap.ordered_keys.len(), 2);

        // Find by wire should work
        let wire1 = pk1.to_wire_bytes();
        let entry = snap.find_by_wire(&wire1).expect("should find pk1");
        assert_eq!(entry.name, "node-alpha");
        assert_eq!(entry.weight, 100);
    }

    #[test]
    fn snapshot_find_by_wire_miss() {
        let reg = ValidatorRegistry::empty();
        let snap = reg.create_snapshot();
        assert!(snap.find_by_wire(&[0x01, 0x02]).is_none());
        assert!(snap.is_empty());
    }

    #[test]
    fn cbor_v1_compat() {
        use noble_codec::NobleCbor;

        let mut list = ValidatorList::new();
        list.add_validator(make_pubkey(), 100, 1_700_000_000);
        list.add_validator(make_pubkey(), 50, 1_700_000_000);

        let bytes = list.to_cbor().unwrap();

        // Load through registry
        let reg = ValidatorRegistry::from_cbor_with_path(&bytes, None).unwrap();
        assert_eq!(reg.len(), 2);
        assert!(!reg.is_dirty());
    }

    #[test]
    fn persist_if_dirty_resets_flag() {
        let tmp = std::env::temp_dir().join("noble_test_registry_persist.cbor");
        let mut reg = ValidatorRegistry::new(ValidatorList::new(), Some(tmp.clone()));
        reg.add_validator(make_pubkey(), 100, 1_700_000_000);
        assert!(reg.is_dirty());

        let written = reg.persist_if_dirty().unwrap();
        assert!(written);
        assert!(!reg.is_dirty());

        // Second call should be no-op
        let written = reg.persist_if_dirty().unwrap();
        assert!(!written);

        // Clean up
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn clone_inner_returns_independent_copy() {
        let mut reg = ValidatorRegistry::empty();
        let pk = make_pubkey();
        reg.add_validator(pk.clone(), 100, 1_700_000_000);

        let cloned = reg.clone_inner();
        assert_eq!(cloned.len(), 1);

        // Mutating registry doesn't affect clone
        reg.remove_validator(&pk);
        assert_eq!(cloned.len(), 1);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn set_priority_order_marks_dirty() {
        let mut reg = ValidatorRegistry::empty();
        let pk1 = make_pubkey();
        let pk2 = make_pubkey();
        reg.add_validator(pk1.clone(), 100, 1_700_000_000);
        reg.add_validator(pk2.clone(), 50, 1_700_000_000);
        reg.dirty = false;

        let order = vec![pk2.to_wire_bytes(), pk1.to_wire_bytes()];
        reg.set_priority_order(order).unwrap();
        assert!(reg.is_dirty());
    }

    #[test]
    fn known_peer_operations_mark_dirty() {
        let mut reg = ValidatorRegistry::empty();
        reg.dirty = false;

        reg.update_known_peer(
            "aabbccdd",
            Some("peer1".into()),
            None,
            None,
            true,
            true,
            None,
            None,
            None,
            1_700_000_000,
        );
        assert!(reg.is_dirty());

        reg.dirty = false;
        assert!(reg.remove_known_peer("aabbccdd"));
        assert!(reg.is_dirty());
    }
}
