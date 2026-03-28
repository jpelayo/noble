// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Badge candidate pool — tracks peers that want to vote but don't have badges yet.
//!
//! Accumulates uptime per candidate. When a candidate exceeds the minimum presence
//! threshold (`BADGE_MIN_PRESENCE_SECS`), the node auto-proposes a badge grant
//! (if no active proposal exists for the candidate).
//!
//! Presence proofs are signed attestations by existing badge holders that they have
//! independently observed the candidate online. Multiple proofs from different vouchers
//! strengthen the proposal.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A candidate for badge granting — tracked locally, NOT on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEntry {
    /// Unix timestamp when this candidate was first seen.
    pub first_seen: u64,
    /// Cumulative seconds the candidate has been observed online.
    pub cumulative_uptime: u64,
    /// Unix timestamp of the last heartbeat (NodeAnnounce or status response).
    pub last_seen: u64,
    /// Friendly name from NodeAnnounce (for logging/display).
    pub node_name: String,
    /// Whether the candidate announced wants_to_vote=true.
    pub wants_to_vote: bool,
}

/// Pool of badge candidates with uptime tracking.
#[derive(Debug, Clone, Default)]
pub struct BadgeCandidatePool {
    /// Wire pubkey bytes → candidate entry.
    candidates: HashMap<Vec<u8>, CandidateEntry>,
}

impl BadgeCandidatePool {
    pub fn new() -> Self {
        Self { candidates: HashMap::new() }
    }

    /// Add or update a candidate from a NodeAnnounce.
    pub fn observe(&mut self, wire: Vec<u8>, node_name: &str, wants_to_vote: bool, now: u64) {
        let entry = self.candidates.entry(wire).or_insert_with(|| CandidateEntry {
            first_seen: now,
            cumulative_uptime: 0,
            last_seen: now,
            node_name: node_name.to_string(),
            wants_to_vote,
        });
        entry.last_seen = now;
        entry.wants_to_vote = wants_to_vote;
        if !node_name.is_empty() {
            entry.node_name = node_name.to_string();
        }
    }

    /// Tick uptime for all candidates that are currently online (seen within `stale_threshold` seconds).
    /// Call this every N seconds (e.g., every 5s from the engine tick).
    pub fn tick_uptime(&mut self, now: u64, tick_interval: u64, stale_threshold: u64) {
        for entry in self.candidates.values_mut() {
            if now.saturating_sub(entry.last_seen) <= stale_threshold {
                entry.cumulative_uptime = entry.cumulative_uptime.saturating_add(tick_interval);
            }
        }
    }

    /// Return candidates that have exceeded the minimum uptime threshold.
    pub fn eligible_candidates(&self, min_uptime_secs: u64) -> Vec<(Vec<u8>, &CandidateEntry)> {
        self.candidates.iter()
            .filter(|(_, e)| e.wants_to_vote && e.cumulative_uptime >= min_uptime_secs)
            .map(|(k, v)| (k.clone(), v))
            .collect()
    }

    /// Remove a candidate (e.g., after badge is granted).
    pub fn remove(&mut self, wire: &[u8]) {
        self.candidates.remove(wire);
    }

    /// Get a candidate entry by wire pubkey.
    pub fn get(&self, wire: &[u8]) -> Option<&CandidateEntry> {
        self.candidates.get(wire)
    }

    /// Number of candidates in the pool.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// All candidates for display/serialization.
    pub fn list_all(&self) -> Vec<(Vec<u8>, &CandidateEntry)> {
        self.candidates.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

/// A signed presence proof — a badge holder vouching for a candidate's uptime.
///
/// Carried as metadata in BadgeProposal or BadgeVote transactions.
/// Multiple proofs from different vouchers accumulate on the same proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceProof {
    /// Wire pubkey of the badge holder who vouches for the candidate.
    pub voucher: Vec<u8>,
    /// Unix timestamp when the voucher first saw the candidate.
    pub first_seen: u64,
    /// Cumulative seconds the voucher observed the candidate online.
    pub observed_uptime: u64,
    /// Signature: sign(SHA-256(candidate_wire || first_seen_le || observed_uptime_le)) by voucher key.
    pub signature: Vec<u8>,
}

impl PresenceProof {
    /// Compute the signing payload for a presence proof.
    pub fn signing_payload(candidate_wire: &[u8], first_seen: u64, observed_uptime: u64) -> Vec<u8> {
        let mut payload = Vec::with_capacity(candidate_wire.len() + 16);
        payload.extend_from_slice(candidate_wire);
        payload.extend_from_slice(&first_seen.to_le_bytes());
        payload.extend_from_slice(&observed_uptime.to_le_bytes());
        payload
    }
}
