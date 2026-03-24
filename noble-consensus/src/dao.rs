// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! DAO governance poll system — on-chain non-binding polls.
//!
//! Badge holders (or all validators during bootstrap) can create polls
//! with a free-text question. Voters cast yes/no/abstain. Results are
//! recorded on-chain but have no automated effect.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single DAO governance poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoPoll {
    /// Deterministic ID: SHA-256(question || proposer_wire || created_at_cycle_be).
    pub poll_id: String,
    /// The governance question (UTF-8, max 500 chars).
    pub question: String,
    /// Wire pubkey of the proposer.
    pub proposer: Vec<u8>,
    /// Cycle when the poll was created.
    pub created_at_cycle: u64,
    /// Cycle when voting closes.
    pub expires_at_cycle: u64,
    /// Wire pubkeys that voted yes.
    pub votes_yes: Vec<Vec<u8>>,
    /// Wire pubkeys that voted no.
    pub votes_no: Vec<Vec<u8>>,
    /// Wire pubkeys that abstained.
    pub votes_abstain: Vec<Vec<u8>>,
    /// "active" or "closed".
    pub status: String,
}

impl DaoPoll {
    /// Record a vote. Returns false if the voter already voted.
    pub fn record_vote(&mut self, voter_wire: Vec<u8>, vote: &str) -> bool {
        // Dedup: check all vote lists
        if self.votes_yes.contains(&voter_wire)
            || self.votes_no.contains(&voter_wire)
            || self.votes_abstain.contains(&voter_wire)
        {
            return false;
        }
        match vote {
            "yes" => self.votes_yes.push(voter_wire),
            "no" => self.votes_no.push(voter_wire),
            "abstain" => self.votes_abstain.push(voter_wire),
            _ => return false,
        }
        true
    }

    /// Total number of unique voters.
    pub fn total_voters(&self) -> usize {
        self.votes_yes.len() + self.votes_no.len() + self.votes_abstain.len()
    }
}

/// In-memory store for DAO polls.
#[derive(Debug, Default)]
pub struct DaoStore {
    polls: HashMap<String, DaoPoll>,
}

impl DaoStore {
    pub fn new() -> Self {
        Self { polls: HashMap::new() }
    }

    /// Insert a new poll. Returns false if poll_id already exists.
    pub fn create_poll(&mut self, poll: DaoPoll) -> bool {
        if self.polls.contains_key(&poll.poll_id) {
            return false;
        }
        self.polls.insert(poll.poll_id.clone(), poll);
        true
    }

    /// Record a vote on a poll. Returns Err with reason if invalid.
    pub fn record_vote(&mut self, poll_id: &str, voter_wire: Vec<u8>, vote: &str) -> Result<(), String> {
        let poll = self.polls.get_mut(poll_id)
            .ok_or_else(|| format!("poll not found: {poll_id}"))?;
        if poll.status != "active" {
            return Err(format!("poll is {}, not active", poll.status));
        }
        if !poll.record_vote(voter_wire, vote) {
            return Err("duplicate vote or invalid vote value".into());
        }
        Ok(())
    }

    /// Close expired polls. Returns number of polls closed.
    pub fn expire_polls(&mut self, current_cycle: u64) -> usize {
        let mut closed = 0;
        for poll in self.polls.values_mut() {
            if poll.status == "active" && current_cycle >= poll.expires_at_cycle {
                poll.status = "closed".to_string();
                closed += 1;
            }
        }
        closed
    }

    /// Get a poll by ID.
    pub fn get(&self, poll_id: &str) -> Option<&DaoPoll> {
        self.polls.get(poll_id)
    }

    /// List all active polls.
    pub fn list_active(&self) -> Vec<&DaoPoll> {
        self.polls.values().filter(|p| p.status == "active").collect()
    }

    /// List closed polls (history), sorted by created_at_cycle DESC.
    pub fn list_history(&self, limit: usize) -> Vec<&DaoPoll> {
        let mut closed: Vec<_> = self.polls.values().filter(|p| p.status == "closed").collect();
        closed.sort_by(|a, b| b.created_at_cycle.cmp(&a.created_at_cycle));
        closed.truncate(limit);
        closed
    }

    /// List all polls (for persistence).
    pub fn list_all(&self) -> Vec<&DaoPoll> {
        self.polls.values().collect()
    }

    /// Load a poll from persistence.
    pub fn insert(&mut self, poll: DaoPoll) {
        self.polls.insert(poll.poll_id.clone(), poll);
    }

    /// Whether any polls exist (for persistence skip).
    pub fn is_empty(&self) -> bool {
        self.polls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_poll() -> DaoPoll {
        DaoPoll {
            poll_id: "abc123".into(),
            question: "Should we increase fees?".into(),
            proposer: vec![0x01; 33],
            created_at_cycle: 100,
            expires_at_cycle: 148,
            votes_yes: vec![],
            votes_no: vec![],
            votes_abstain: vec![],
            status: "active".into(),
        }
    }

    #[test]
    fn create_and_vote() {
        let mut store = DaoStore::new();
        assert!(store.create_poll(make_poll()));
        assert!(!store.create_poll(make_poll())); // duplicate

        let voter = vec![0x02; 33];
        assert!(store.record_vote("abc123", voter.clone(), "yes").is_ok());
        assert!(store.record_vote("abc123", voter.clone(), "no").is_err()); // duplicate

        let poll = store.get("abc123").unwrap();
        assert_eq!(poll.votes_yes.len(), 1);
        assert_eq!(poll.total_voters(), 1);
    }

    #[test]
    fn expire_polls() {
        let mut store = DaoStore::new();
        store.create_poll(make_poll());
        assert_eq!(store.expire_polls(147), 0); // not expired yet
        assert_eq!(store.expire_polls(148), 1); // expired
        assert_eq!(store.get("abc123").unwrap().status, "closed");
    }

    #[test]
    fn vote_on_closed_poll_rejected() {
        let mut store = DaoStore::new();
        store.create_poll(make_poll());
        store.expire_polls(200);
        let err = store.record_vote("abc123", vec![0x03; 33], "yes").unwrap_err();
        assert!(err.contains("closed"));
    }
}
