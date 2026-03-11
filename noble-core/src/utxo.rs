// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin-style UTXO types for the NOBLE protocol.
//!
//! Every coin in the system is represented as an unspent transaction output (UTXO).
//! Transactions consume UTXOs (via inputs) and create new ones (via outputs).
//! There are no account balances — balance = sum of UTXOs for an address.

use serde::{Deserialize, Serialize};

use noble_crypto::Hash256;

use crate::address::NobleAddress;

/// Reference to a specific output of a previous transaction.
///
/// 36 bytes on wire: txid (32B) || vout (4B LE).
/// Equivalent to Bitcoin's `COutPoint`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Transaction ID containing the output.
    pub txid: Hash256,
    /// Zero-based index into that transaction's outputs array.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint used in coinbase transaction inputs.
    /// txid = all zeros, vout = 0xFFFFFFFF.
    pub const COINBASE_PREVOUT: Self = Self {
        txid: Hash256::ZERO,
        vout: 0xFFFF_FFFF,
    };

    /// Whether this outpoint references the null coinbase input.
    pub fn is_coinbase(&self) -> bool {
        self.txid == Hash256::ZERO && self.vout == 0xFFFF_FFFF
    }

    /// Serialize to 36 bytes: txid (32B) || vout (4B LE).
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(self.txid.as_bytes());
        buf[32..36].copy_from_slice(&self.vout.to_le_bytes());
        buf
    }

    /// Deserialize from 36 bytes.
    pub fn from_bytes(bytes: &[u8; 36]) -> Self {
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&bytes[..32]);
        let txid = Hash256::from_bytes(txid_bytes);
        let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        Self { txid, vout }
    }
}

/// A transaction input: reference to a UTXO being spent.
///
/// Unlike Bitcoin, NOBLE uses a single transaction-level signature (`publisher_sig`)
/// rather than per-input scriptSig/witness data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    /// Reference to the UTXO being consumed.
    pub prev_output: OutPoint,
}

/// A transaction output: creates a new UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// Value in atomic units (1 NOBLE = 1,000,000 atomic).
    pub value: u64,
    /// Owner address. The holder of the corresponding private key can spend this output.
    pub address: NobleAddress,
}

/// A UTXO entry stored in the persistent UTXO set.
///
/// This is the value stored in `CF_UTXO_SET`, keyed by `OutPoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    /// Output value in atomic units.
    pub value: u64,
    /// Owner address.
    pub address: NobleAddress,
    /// Block height where this UTXO was created.
    pub height: u64,
    /// Whether this output came from a coinbase transaction.
    pub is_coinbase: bool,
}

impl UtxoEntry {
    /// Whether this coinbase output has reached maturity and can be spent.
    ///
    /// Non-coinbase outputs are always mature. Coinbase outputs require
    /// `COINBASE_MATURITY` confirmations before they can be referenced as inputs.
    pub fn is_mature(&self, current_height: u64) -> bool {
        if !self.is_coinbase {
            return true;
        }
        current_height >= self.height + crate::constants::COINBASE_MATURITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outpoint_coinbase_detection() {
        assert!(OutPoint::COINBASE_PREVOUT.is_coinbase());

        let regular = OutPoint {
            txid: Hash256::from_bytes([0xAB; 32]),
            vout: 0,
        };
        assert!(!regular.is_coinbase());
    }

    #[test]
    fn outpoint_coinbase_zero_txid_wrong_vout() {
        let not_coinbase = OutPoint {
            txid: Hash256::ZERO,
            vout: 0,
        };
        assert!(!not_coinbase.is_coinbase());
    }

    #[test]
    fn outpoint_serialization_roundtrip() {
        let op = OutPoint {
            txid: Hash256::from_bytes([0xAB; 32]),
            vout: 42,
        };
        let bytes = op.to_bytes();
        let decoded = OutPoint::from_bytes(&bytes);
        assert_eq!(op, decoded);
    }

    #[test]
    fn outpoint_coinbase_serialization() {
        let bytes = OutPoint::COINBASE_PREVOUT.to_bytes();
        let decoded = OutPoint::from_bytes(&bytes);
        assert!(decoded.is_coinbase());
    }

    #[test]
    fn outpoint_bytes_length() {
        let bytes = OutPoint::COINBASE_PREVOUT.to_bytes();
        assert_eq!(bytes.len(), 36);
    }

    #[test]
    fn txout_basic() {
        let out = TxOut {
            value: 100_000_000,
            address: NobleAddress::Noble(
                {
                let (_, pk) = noble_crypto::ed25519::generate_keypair();
                noble_crypto::NoblePublicKey::Ed25519(pk)
            },
            ),
        };
        assert_eq!(out.value, 100_000_000);
    }

    #[test]
    fn utxo_entry_maturity_non_coinbase() {
        let entry = UtxoEntry {
            value: 1000,
            address: NobleAddress::Noble(
                {
                let (_, pk) = noble_crypto::ed25519::generate_keypair();
                noble_crypto::NoblePublicKey::Ed25519(pk)
            },
            ),
            height: 100,
            is_coinbase: false,
        };
        // Non-coinbase is always mature
        assert!(entry.is_mature(0));
        assert!(entry.is_mature(100));
        assert!(entry.is_mature(1000));
    }

    #[test]
    fn utxo_entry_maturity_coinbase() {
        let entry = UtxoEntry {
            value: 100_000_000,
            address: NobleAddress::Noble(
                {
                let (_, pk) = noble_crypto::ed25519::generate_keypair();
                noble_crypto::NoblePublicKey::Ed25519(pk)
            },
            ),
            height: 10,
            is_coinbase: true,
        };
        // COINBASE_MATURITY = 6, created at height 10
        // Mature at height 10 + 6 = 16
        assert!(!entry.is_mature(10));
        assert!(!entry.is_mature(15));
        assert!(entry.is_mature(16));
        assert!(entry.is_mature(100));
    }

    #[test]
    fn outpoint_hash_set_dedup() {
        use std::collections::HashSet;
        let op1 = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 0,
        };
        let op2 = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 0,
        };
        let op3 = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 1,
        };
        let mut set = HashSet::new();
        set.insert(op1.clone());
        set.insert(op2);
        set.insert(op3);
        assert_eq!(set.len(), 2); // op1 == op2, op3 is different
    }
}
