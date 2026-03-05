// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Cycle history tracking (H-002).
//!
//! Records the outcome of each consensus cycle for later retrieval via RPC.

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// Historical record of a single consensus cycle's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleHistoryEntry {
    /// The cycle number.
    pub cycle_number: u64,
    /// Outcome status: "finalized" or "indeterminate".
    pub status: String,
    /// Block proposals received during the cycle.
    pub proposals: Vec<CycleProposal>,
    /// Vote tallies per candidate.
    pub votes: Vec<CycleVoteTally>,
    /// Friendly name of the winning validator (if any).
    pub winner: Option<String>,
    /// Hash of the winning block (if any).
    pub winning_hash: Option<Hash256>,
    /// Whether disambiguation (tiebreaker) was needed.
    pub disambiguation: bool,
    /// Unix timestamp when the cycle was finalized.
    pub finalized_at: u64,
}

/// A block proposal within a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleProposal {
    /// Hex-encoded validator public key.
    pub validator: String,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Number of transactions in the proposed block.
    pub tx_count: u32,
}

/// Vote tally for a candidate block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleVoteTally {
    /// Hash of the candidate block.
    pub block_hash: Hash256,
    /// Hex-encoded validator who proposed this block.
    pub validator: String,
    /// Number of R1 votes received.
    pub vote_count: usize,
    /// Number of R2 (confirmation) votes received.
    #[serde(default)]
    pub r2_vote_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;

    #[test]
    fn cycle_history_entry_cbor_roundtrip() {
        let entry = CycleHistoryEntry {
            cycle_number: 42,
            status: "finalized".to_string(),
            proposals: vec![CycleProposal {
                validator: "abcd".to_string(),
                block_hash: Hash256::from_bytes([0x11; 32]),
                tx_count: 5,
            }],
            votes: vec![CycleVoteTally {
                block_hash: Hash256::from_bytes([0x11; 32]),
                validator: "abcd".to_string(),
                vote_count: 3,
                r2_vote_count: 2,
            }],
            winner: Some("validator-1".to_string()),
            winning_hash: Some(Hash256::from_bytes([0x11; 32])),
            disambiguation: false,
            finalized_at: 1_700_000_000,
        };

        let bytes = entry.to_cbor().unwrap();
        let decoded = CycleHistoryEntry::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.cycle_number, 42);
        assert_eq!(decoded.status, "finalized");
        assert_eq!(decoded.proposals.len(), 1);
        assert_eq!(decoded.votes.len(), 1);
        assert_eq!(decoded.winner.as_deref(), Some("validator-1"));
        assert!(!decoded.disambiguation);
    }

    #[test]
    fn indeterminate_entry_cbor_roundtrip() {
        let entry = CycleHistoryEntry {
            cycle_number: 99,
            status: "indeterminate".to_string(),
            proposals: vec![],
            votes: vec![],
            winner: None,
            winning_hash: None,
            disambiguation: false,
            finalized_at: 1_700_001_000,
        };

        let bytes = entry.to_cbor().unwrap();
        let decoded = CycleHistoryEntry::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.cycle_number, 99);
        assert_eq!(decoded.status, "indeterminate");
        assert!(decoded.winner.is_none());
        assert!(decoded.winning_hash.is_none());
    }
}
