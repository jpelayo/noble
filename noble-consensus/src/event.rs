// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Input events and output actions for the consensus state machine.

use noble_core::{Block, Transaction};
use noble_crypto::Hash256;

use crate::cycle::CyclePhase;
use crate::vote::PorVote;

/// Input events consumed by the consensus engine.
#[derive(Debug)]
pub enum CycleEvent {
    /// The cycle has transitioned to a new phase.
    PhaseTransition { cycle: u64, new_phase: CyclePhase },
    /// A full cycle has completed (transition to next cycle).
    CycleBoundary { completed_cycle: u64 },
    /// A peer proposed a block.
    BlockProposed {
        block: Box<Block>,
        from_peer: Vec<u8>,
    },
    /// A peer broadcast a vote.
    VoteReceived { vote: PorVote, from_peer: Vec<u8> },
    /// Timer tick with the current timestamp.
    Tick { now: u64 },
    /// Response from node: mempool transactions for block proposal (P0.3).
    MempoolTransactions(Vec<Transaction>),
}

/// Output actions emitted by the consensus engine.
#[derive(Debug)]
pub enum CycleIo {
    /// Broadcast a proposed block to all peers.
    BroadcastBlock(Box<Block>),
    /// Broadcast a vote to all peers.
    BroadcastVote(PorVote),
    /// Commit a winning block to storage.
    CommitBlock(Box<Block>),
    /// Re-admit transactions from losing candidates back to the mempool.
    ReadmitTransactions(Vec<Transaction>),
    /// Request the node event loop to schedule a timer.
    SetTimer { duration_secs: u64 },
    /// Ban a peer for misbehavior.
    BanPeer { peer_id: Vec<u8>, reason: String },
    /// Request a specific block from a peer.
    RequestBlock {
        peer_id: Vec<u8>,
        block_hash: Hash256,
    },
    /// Emit an observable metric.
    EmitMetric { name: String, value: f64 },
    /// Log a message.
    Log(String),
    /// Request mempool transactions from the node for block proposal (P0.3).
    RequestMempoolTransactions { max_count: usize },
}
