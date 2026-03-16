// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction type registry — centralizes all type-specific behavior.
//!
//! Each transaction type (notarization, transfer, coinbase, etc.) implements
//! [`TxTypeHandler`] which declares its validation rules, field requirements,
//! and display name. The [`handler_for`] function returns the handler for a
//! given `tx_type` byte.
//!
//! To add a new transaction type:
//! 1. Create a new file in this module (e.g., `sealed_reveal.rs`)
//! 2. Implement `TxTypeHandler` for a unit struct
//! 3. Add the constant to `constants.rs`
//! 4. Add to the match in `handler_for()`

mod notarization;
mod transfer;
mod key_rotation;
mod badge_proposal;
mod badge_vote;
mod badge_revocation;
mod coinbase;
mod locked;
mod unlocking;

pub use notarization::Notarization;
pub use transfer::Transfer;
pub use key_rotation::KeyRotation;
pub use badge_proposal::BadgeProposal;
pub use badge_vote::BadgeVote;
pub use badge_revocation::BadgeRevocation;
pub use coinbase::Coinbase;
pub use locked::Locked;
pub use unlocking::Unlocking;

use crate::constants::*;

/// Declares type-specific behavior for a transaction type.
///
/// Generic validation (signature, UTXO balance, version) is handled
/// separately in `validation.rs`. This trait covers only the rules
/// that differ per type.
pub trait TxTypeHandler: Send + Sync {
    /// The `tx_type` byte this handler covers.
    fn type_id(&self) -> u8;

    /// Human-readable name for display and API responses.
    fn name(&self) -> &'static str;

    /// Whether this type requires a non-zero checksum (document hash).
    fn requires_checksum(&self) -> bool { false }

    /// Whether checksum must be zero (no document association).
    fn requires_zero_checksum(&self) -> bool { false }

    /// Whether at least one output is required.
    fn requires_outputs(&self) -> bool { false }

    /// Whether `encrypted_locator` is allowed.
    fn allows_encrypted_locator(&self) -> bool { false }

    /// Whether `external_attestations` is allowed.
    fn allows_external_attestations(&self) -> bool { false }

    /// Whether `metadata` version chain validation applies.
    fn validates_version_chain(&self) -> bool { false }

    /// Whether this is a coinbase (block reward) transaction.
    fn is_coinbase(&self) -> bool { false }

    /// Whether this type needs notarization-specific storage indexing
    /// (checksum index, version chain, publisher index).
    fn needs_notarization_indexing(&self) -> bool { false }

    /// Whether BIP-137 signing uses the transfer message format
    /// (recipient + amount) vs the notarization format (checksum).
    fn uses_transfer_bip137_message(&self) -> bool { false }

    /// Whether `contract_data` is allowed on this transaction type.
    fn allows_contract_data(&self) -> bool { false }
}

/// Look up the handler for a given `tx_type` byte.
///
/// Returns `None` for unrecognized types (validation rejects them).
pub fn handler_for(tx_type: u8) -> Option<&'static dyn TxTypeHandler> {
    match tx_type {
        TX_TYPE_NOTARIZATION => Some(&Notarization),
        TX_TYPE_TRANSFER => Some(&Transfer),
        TX_TYPE_KEY_ROTATION => Some(&KeyRotation),
        TX_TYPE_BADGE_PROPOSAL => Some(&BadgeProposal),
        TX_TYPE_BADGE_VOTE => Some(&BadgeVote),
        TX_TYPE_BADGE_REVOCATION => Some(&BadgeRevocation),
        TX_TYPE_COINBASE => Some(&Coinbase),
        TX_TYPE_LOCKED => Some(&Locked),
        TX_TYPE_UNLOCKING => Some(&Unlocking),
        _ => None,
    }
}

/// Return the human-readable name for a `tx_type` byte.
///
/// Returns `"Unknown"` for unrecognized types.
pub fn type_name(tx_type: u8) -> &'static str {
    handler_for(tx_type).map_or("Unknown", |h| h.name())
}

/// Check whether a `tx_type` byte is recognized.
pub fn is_known_type(tx_type: u8) -> bool {
    handler_for(tx_type).is_some()
}
