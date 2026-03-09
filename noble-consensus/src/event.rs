// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Input events and output actions for the consensus state machine.

use noble_core::{Block, Transaction};
use noble_crypto::Hash256;

use crate::cycle::CyclePhase;
use crate::history::BlockVotes;
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
    /// Fork status update from node (peer chain tip data).
    ForkStatus {
        local_height: u64,
        forks: Vec<crate::fork_resolver::ForkInfo>,
        total_peers: usize,
    },
    /// Cross-chain fork status from discovered_blockchains.
    CrossChainStatus {
        local_chain_id: u32,
        local_height: u64,
        local_vote_weight: u64,
        same_chain_peer_count: usize,
        cross_chain_forks: Vec<crate::fork_resolver::CrossChainForkInfo>,
    },
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
    BanPeer {
        peer_id: Vec<u8>,
        category: noble_core::BanCategoryCode,
        reason: String,
    },
    /// Request a specific block from a peer.
    RequestBlock {
        peer_id: Vec<u8>,
        block_hash: Hash256,
    },
    /// Request a specific block from ALL connected peers.
    /// Used when a vote references an unknown candidate — the voter may not
    /// have the block cached, so we broadcast the request to maximise the
    /// chance of obtaining the block body before the cycle boundary.
    RequestBlockFromAll {
        block_hash: Hash256,
    },
    /// Emit an observable metric.
    EmitMetric { name: String, value: f64 },
    /// Log a message.
    Log(String),
    /// Request mempool transactions from the node for block proposal (P0.3).
    RequestMempoolTransactions { max_count: usize },
    /// Evict transactions that failed validation during self-proposal.
    EvictTransactions(Vec<Hash256>),
    /// Persist badge state changes to storage.
    /// Contains list of (pubkey_wire, cbor_badge_bytes) for upserts and
    /// list of proposal (hash_hex, cbor_proposal_bytes) for upserts.
    PersistBadgeState {
        badges: Vec<(Vec<u8>, Vec<u8>)>,
        proposals: Vec<(String, Vec<u8>)>,
    },
    /// Store per-block vote witness data.
    /// Emitted alongside CommitBlock so each committed block has a permanent
    /// record of which validators voted for it (survives ClearCycleHistory).
    StoreBlockVotes {
        height: u64,
        votes: Box<BlockVotes>,
    },
    /// Clear all cycle history from storage.
    /// Emitted when block 1 commits and the cycle epoch changes, so stale
    /// history entries from the bootstrap epoch are purged.
    ClearCycleHistory,
    /// Notify the node that the consensus phase has changed.
    /// Used to broadcast phase transitions to GUI/WebSocket subscribers.
    PhaseChanged { cycle: u64, phase: CyclePhase },
    /// Persist finality state to storage.
    PersistFinalityState { height: u64, hash: Hash256, cycle: u64 },
    /// Publish misbehavior evidence to the network and store locally.
    PublishEvidence(Box<noble_core::MisbehaviorEvidence>),
    /// Request automatic fork resolution (reset + re-sync).
    RequestForkResolution {
        target_hash: Hash256,
        target_height: u64,
        reason: String,
    },
    /// Persist a checkpoint to storage.
    PersistCheckpoint(Box<crate::checkpoint::Checkpoint>),
    /// Notify that checkpoints have activated.
    CheckpointsActivated { heights: Vec<u64> },
    /// Request cross-chain adoption: wipe all data and re-sync from a different chain.
    RequestChainAdoption {
        target_chain_id: u32,
        reason: String,
    },
}
