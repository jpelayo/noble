// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction, Block, BlockHeader, Merkle tree and validation rules for the NOBLE protocol.

pub mod block;
pub mod constants;
pub mod error;
pub mod genesis;
pub mod merkle;
pub mod metadata;
pub mod node_announce;
pub mod transaction;
pub mod validation;

pub use block::{Block, BlockHeader};
pub use constants::*;
pub use error::ValidationError;
pub use genesis::{genesis_block, genesis_hash, testnet_genesis_block, testnet_genesis_hash};
pub use merkle::{compute_merkle_root, MerkleProof};
pub use metadata::{validate_metadata, MetadataEntry};
pub use node_announce::{NodeAnnounce, NodeRole, OrgType};
pub use transaction::Transaction;
pub use validation::{
    validate_block, validate_transaction, BlockValidationContext, TxValidationContext,
};
