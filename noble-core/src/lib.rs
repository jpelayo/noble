// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction, Block, BlockHeader, Merkle tree and validation rules for the NOBLE protocol.

pub mod address;
pub mod block;
pub mod constants;
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
pub mod tx_types;
pub mod utxo;
pub mod validation;
pub mod wire;

pub use address::{AddressError, NobleAddress};
pub use block::{Block, BlockHeader};
pub use constants::*;
pub use encrypted_locator::{EncryptedLocator, ExternalAttestation, LocatorRecipient};
pub use error::ValidationError;
pub use evidence::{
    AnnounceContradiction, AnnounceEquivocationEvidence, BanCategoryCode,
    DoubleProposalEvidence, EvidenceError, InvalidBlockCode, InvalidBlockEvidence,
    MisbehaviorEvidence, VoteEquivocationEvidence,
};
pub use genesis::{build_genesis, derive_chain_id, GENESIS_TIMESTAMP};
pub use merkle::{compute_merkle_root, MerkleProof};
pub use metadata::{validate_metadata, validate_version_metadata, MetadataEntry};
pub use node_announce::{compute_pki_binding_message_for_key, NodeAnnounce, NodeRole, OrgType};
pub use peer_record::PeerRecord;
pub use pst::{PartiallySignedTransaction, PstError, SignerEntry, SignerRole, PST_VERSION};
pub use transaction::Transaction;
pub use utxo::{OutPoint, TxIn, TxOut, UtxoEntry};
pub use validation::{
    median_timestamp, validate_block, validate_block_timestamp, validate_source_address,
    validate_transaction, BlockValidationContext, TxValidationContext,
};
