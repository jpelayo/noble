// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction, Block, BlockHeader, Merkle tree and validation rules for the NOBLE protocol.

pub mod address;
pub mod block;
pub mod constants;
pub mod debit;
pub mod paths;
pub mod encrypted_locator;
pub mod error;
pub mod evidence;
pub mod genesis;
pub mod merkle;
pub mod metadata;
pub mod node_announce;
pub mod peer_record;
pub mod pst;
pub mod transaction;
pub mod validation;

pub use address::{AddressError, NobleAddress};
pub use block::{Block, BlockHeader};
pub use constants::*;
pub use debit::{resolve_debit_address, resolve_debit_address_enforced, DebitError};
pub use encrypted_locator::{EncryptedLocator, ExternalAttestation, LocatorRecipient};
pub use error::ValidationError;
pub use evidence::{
    DoubleProposalEvidence, EvidenceError, MisbehaviorEvidence, VoteEquivocationEvidence,
};
pub use genesis::{
    derive_chain_id, genesis_block, genesis_hash, mainnet_chain_id, regtest_chain_id,
    regtest_genesis_block, regtest_genesis_hash, testnet_chain_id, testnet_genesis_block,
    testnet_genesis_hash, GENESIS_TIMESTAMP,
};
pub use merkle::{compute_merkle_root, MerkleProof};
pub use metadata::{validate_metadata, validate_version_metadata, MetadataEntry};
pub use node_announce::{compute_pki_binding_message_for_key, NodeAnnounce, NodeRole, OrgType};
pub use peer_record::PeerRecord;
pub use pst::{PartiallySignedTransaction, PstError, SignerEntry, SignerRole, PST_VERSION};
pub use transaction::Transaction;
pub use validation::{
    median_timestamp, validate_block, validate_block_timestamp, validate_source_address,
    validate_transaction, BlockValidationContext, TxValidationContext,
};
