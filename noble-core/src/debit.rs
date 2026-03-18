// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical debit address resolution for NOBLE transactions (S34).
//!
//! This module provides a single `resolve_debit_address()` function used by
//! all debit paths (mempool admission, storage commit, and chain replay) to
//! determine which balance bucket a transaction debits from.
//!
//! # Motivation
//!
//! Before S34, each debit site duplicated the Hash160 fallback logic inline.
//! The replay paths (both memory and RocksDB) were missing the fallback,
//! causing a P0 rollback/replay divergence bug: balances after replay could
//! differ from balances after the original commit.
//!
//! # Resolution Logic
//!
//! 1. **Explicit mode** (S34+): If `tx.source_address` is `Some(wire_bytes)`,
//!    decode the wire bytes as a `NobleAddress` and return it directly.
//!    The chosen bucket is committed into the transaction signature.
//!
//! 2. **Legacy mode** (pre-S34 or `source_address` absent):
//!    - Start with `NobleAddress::Noble(sender_pk)`.
//!    - For secp256k1 senders, if the Noble bucket has insufficient balance,
//!      fall back to the `BitcoinHash160` bucket.
//!    - Senders without a Bitcoin alias always use the Noble bucket.

use crate::address::NobleAddress;
use noble_crypto::keys::NoblePublicKey;

/// Errors from debit address resolution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DebitError {
    /// The `source_address` wire bytes are not a valid `NobleAddress`.
    #[error("invalid source_address: {0}")]
    InvalidSourceAddress(String),

    /// Post-activation: secp256k1 sender must specify `source_address`.
    #[error("source_address required for secp256k1 senders at this block height")]
    SourceAddressRequired,

    /// The resolved bucket has insufficient balance.
    #[error("insufficient balance in {bucket}: have {have}, need {need}")]
    InsufficientBalance {
        bucket: String,
        have: u64,
        need: u64,
    },
}

/// Resolve which balance bucket a transaction should debit from.
///
/// # Parameters
///
/// - `source_address_wire`: the transaction's `source_address` field (raw wire bytes)
/// - `sender_pk`: the issuer's public key (extracted from signature envelope)
/// - `need`: total amount to debit (amount + fee)
/// - `balance_of`: closure that returns the current balance of any `NobleAddress`
///
/// # Returns
///
/// The `NobleAddress` whose balance bucket should be debited.
pub fn resolve_debit_address<F>(
    source_address_wire: &Option<Vec<u8>>,
    sender_pk: &NoblePublicKey,
    need: u64,
    balance_of: F,
) -> Result<NobleAddress, DebitError>
where
    F: Fn(&NobleAddress) -> u64,
{
    // Phase 1: Explicit source_address takes priority
    if let Some(wire) = source_address_wire {
        let addr = NobleAddress::from_wire_bytes(wire)
            .map_err(|e| DebitError::InvalidSourceAddress(e.to_string()))?;
        return Ok(addr);
    }

    // Legacy fallback: Noble first, Hash160 for secp256k1 if needed
    let noble_addr = NobleAddress::Noble(sender_pk.clone());

    if let Some(btc_addr) = NobleAddress::bitcoin_hash160_for_pubkey(sender_pk) {
        let noble_bal = balance_of(&noble_addr);
        if noble_bal >= need {
            Ok(noble_addr)
        } else {
            Ok(btc_addr)
        }
    } else {
        // No Bitcoin alias — only Noble bucket exists
        Ok(noble_addr)
    }
}

/// Resolve debit address with post-activation enforcement.
///
/// Same as `resolve_debit_address` but returns `DebitError::SourceAddressRequired`
/// when the sender is secp256k1, `source_address` is absent, and the block height
/// is at or above the activation height.
pub fn resolve_debit_address_enforced<F>(
    source_address_wire: &Option<Vec<u8>>,
    sender_pk: &NoblePublicKey,
    need: u64,
    block_height: u64,
    activation_height: u64,
    balance_of: F,
) -> Result<NobleAddress, DebitError>
where
    F: Fn(&NobleAddress) -> u64,
{
    // Post-activation: secp256k1 senders MUST specify source_address
    if block_height >= activation_height
        && source_address_wire.is_none()
        && matches!(sender_pk, NoblePublicKey::Secp256k1(_))
    {
        return Err(DebitError::SourceAddressRequired);
    }

    resolve_debit_address(source_address_wire, sender_pk, need, balance_of)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{secp256k1, secp256k1};

    fn make_secp_pk() -> NoblePublicKey {
        let (_, pk) = secp256k1::generate_keypair();
        NoblePublicKey::Secp256k1(pk)
    }

    fn make_ed_pk() -> NoblePublicKey {
        let (_, pk) = secp256k1::generate_keypair();
        NoblePublicKey::Secp256k1(pk)
    }

    #[test]
    fn resolve_with_source_address_noble() {
        let pk = make_ed_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());
        let wire = noble_addr.to_wire_bytes();

        let result = resolve_debit_address(&Some(wire), &pk, 100, |_| 0);
        assert_eq!(result.unwrap(), noble_addr);
    }

    #[test]
    fn resolve_with_source_address_hash160() {
        let pk = make_secp_pk();
        let h160_addr = NobleAddress::bitcoin_hash160_for_pubkey(&pk).unwrap();
        let wire = h160_addr.to_wire_bytes();

        let result = resolve_debit_address(&Some(wire), &pk, 100, |_| 0);
        assert_eq!(result.unwrap(), h160_addr);
    }

    #[test]
    fn resolve_with_source_address_taproot() {
        let pk = make_secp_pk();
        // BIP-341: use the tweaked output key, not raw x-only
        let taproot_addr = NobleAddress::bitcoin_taproot_for_pubkey(&pk).unwrap();
        let wire = taproot_addr.to_wire_bytes();

        let result = resolve_debit_address(&Some(wire), &pk, 100, |_| 0);
        assert_eq!(result.unwrap(), taproot_addr);
    }

    #[test]
    fn resolve_legacy_noble_sufficient() {
        let pk = make_secp_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());

        let result = resolve_debit_address(&None, &pk, 100, |addr| {
            if *addr == noble_addr { 200 } else { 0 }
        });
        assert_eq!(result.unwrap(), noble_addr);
    }

    #[test]
    fn resolve_legacy_hash160_fallback() {
        let pk = make_secp_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());
        let h160_addr = NobleAddress::bitcoin_hash160_for_pubkey(&pk).unwrap();

        // Noble has 50 (not enough), Hash160 has 500
        let result = resolve_debit_address(&None, &pk, 100, |addr| {
            if *addr == noble_addr {
                50
            } else if *addr == h160_addr {
                500
            } else {
                0
            }
        });
        assert_eq!(result.unwrap(), h160_addr);
    }

    #[test]
    fn resolve_legacy_secp256k1_no_fallback() {
        let pk = make_ed_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());

        // No Bitcoin alias — always uses Noble, even if balance is 0
        let result = resolve_debit_address(&None, &pk, 100, |_| 0);
        assert_eq!(result.unwrap(), noble_addr);
    }

    #[test]
    fn resolve_invalid_source_wire_bytes() {
        let pk = make_ed_pk();
        let result = resolve_debit_address(&Some(vec![0xFF, 0x01, 0x02]), &pk, 100, |_| 0);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), DebitError::InvalidSourceAddress(_)),
            "should be InvalidSourceAddress"
        );
    }

    #[test]
    fn enforced_below_activation_source_optional() {
        let pk = make_secp_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());

        let result = resolve_debit_address_enforced(
            &None,
            &pk,
            100,
            999,  // below activation
            1000, // activation height
            |addr| if *addr == noble_addr { 200 } else { 0 },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforced_at_activation_source_required_secp256k1() {
        let pk = make_secp_pk();

        let result = resolve_debit_address_enforced(
            &None,
            &pk,
            100,
            1000, // at activation
            1000,
            |_| 200,
        );
        assert!(matches!(result.unwrap_err(), DebitError::SourceAddressRequired));
    }

    #[test]
    fn enforced_at_activation_secp256k1_exempt() {
        let pk = make_ed_pk();
        let noble_addr = NobleAddress::Noble(pk.clone());

        let result = resolve_debit_address_enforced(
            &None,
            &pk,
            100,
            1000, // at activation
            1000,
            |addr| if *addr == noble_addr { 200 } else { 0 },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn source_insufficient_no_cross_bucket_rescue() {
        // Explicit source_address = Hash160 with 50, Noble has 200.
        // The function returns Hash160 — it does NOT cross-bucket rescue.
        let pk = make_secp_pk();
        let h160_addr = NobleAddress::bitcoin_hash160_for_pubkey(&pk).unwrap();
        let wire = h160_addr.to_wire_bytes();

        let result = resolve_debit_address(&Some(wire), &pk, 100, |_| 0);
        // Returns Hash160 address — the caller must check balance sufficiency
        assert_eq!(result.unwrap(), h160_addr);
    }
}
