// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for the consensus engine.

use thiserror::Error;

/// Errors returned by the consensus engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConsensusError {
    /// A validator proposed more than one block in the same cycle.
    #[error("duplicate proposal from validator in cycle {0}")]
    DuplicateProposal(u64),

    /// A proposed block failed validation.
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// A received vote failed signature verification.
    #[error("invalid vote: {0}")]
    InvalidVote(String),

    /// Not enough peers connected to participate in consensus (GAP-C6).
    #[error("insufficient peers for consensus (have {have}, need {need})")]
    InsufficientPeers { have: usize, need: usize },

    /// This node is not a validator and cannot produce blocks or votes.
    #[error("node is not a validator")]
    NotValidator,

    /// Action is not valid in the current consensus phase.
    #[error("wrong phase for this action: {0}")]
    WrongPhase(String),

    /// Error from the storage layer.
    #[error("storage: {0}")]
    Storage(String),

    /// Error from the crypto layer.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Catch-all internal error.
    #[error("internal: {0}")]
    Internal(String),
}
