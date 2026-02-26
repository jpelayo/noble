// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Proof of Reputation cycle engine, vote management and fork tracking for the NOBLE protocol.

pub mod badge;
pub mod candidate;
pub mod config;
pub mod cycle;
pub mod engine;
pub mod error;
pub mod event;
pub mod history;
pub mod proposal;
pub mod reputation;
pub mod strategy;
pub mod validator;
pub mod vote;

pub use badge::{
    BadgeStatus, BadgeStore, RevocationReason, SuspensionNotice, SuspensionReason, VoteBadge,
};
pub use candidate::CandidateTracker;
pub use config::ConsensusConfig;
pub use cycle::{CycleManager, CyclePhase};
pub use engine::{ConsensusStateMachine, CycleEngine};
pub use error::ConsensusError;
pub use event::{CycleEvent, CycleIo};
pub use history::{CycleHistoryEntry, CycleProposal, CycleVoteTally};
pub use proposal::propose_block;
pub use reputation::{ReputationData, ReputationEngine};
pub use strategy::VotingStrategy;
pub use validator::{PendingRotation, ValidatorList, ValidatorLiveness};
pub use vote::{ConsensusStrength, MigrationResult, PorVote, VoteError, VoteManager};
