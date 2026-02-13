// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder — constructs and signs notarization and transfer transactions.

use noble_core::{
    MetadataEntry, Transaction, MIN_TX_FEE, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION,
    TX_TYPE_TRANSFER,
};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};

use crate::error::WalletError;
use crate::keystore::KeyStore;

/// Static-like namespace for building signed transactions.
pub struct TransactionBuilder;

impl TransactionBuilder {
    /// Build a signed notarization transaction.
    pub fn build_notarization(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        checksum: Hash256,
        fee: u64,
        metadata: Vec<MetadataEntry>,
    ) -> Result<Transaction, WalletError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            checksum,
            timestamp,
            fee,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: signer.scheme_id(),
                public_key: signer.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
        };

        let msg = tx
            .compute_signing_message()
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(tx)
    }

    /// Build a signed transfer transaction.
    pub fn build_transfer(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        recipient: NoblePublicKey,
        amount: u64,
        fee: u64,
        memo: Option<String>,
    ) -> Result<Transaction, WalletError> {
        if amount == 0 {
            return Err(WalletError::InvalidRecipient("amount must be > 0".into()));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let checksum = Hash256::ZERO; // transfers use zero checksum
        let mut metadata = vec![];
        if let Some(m) = memo {
            metadata.push(MetadataEntry {
                key: "memo".into(),
                value: m.into_bytes(),
            });
        }

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum,
            timestamp,
            fee,
            recipient: Some(recipient),
            amount: Some(amount),
            publisher_sig: SignatureEnvelope {
                scheme_id: signer.scheme_id(),
                public_key: signer.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
        };

        let msg = tx
            .compute_signing_message()
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(tx)
    }

    /// Estimate fee based on mempool fullness (placeholder).
    /// Returns (low, medium, high) fee estimates.
    pub fn estimate_fee() -> (u64, u64, u64) {
        (MIN_TX_FEE, MIN_TX_FEE * 2, MIN_TX_FEE * 5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::SCHEME_ED25519;
    use tempfile::tempdir;

    /// Helper: create an unlocked keystore with one Ed25519 key.
    fn setup_keystore() -> (crate::keystore::KeyStore, NoblePublicKey) {
        let dir = tempdir().unwrap();
        let mut ks = crate::keystore::KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("test-pass").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "test-pass").unwrap();
        (ks, pk)
    }

    #[test]
    fn build_notarization_valid() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xAB; 32]);
        let tx =
            TransactionBuilder::build_notarization(&ks, &pk, checksum, MIN_TX_FEE, vec![]).unwrap();

        assert_eq!(tx.version, PROTOCOL_VERSION);
        assert_eq!(tx.tx_type, TX_TYPE_NOTARIZATION);
        assert_eq!(tx.checksum, checksum);
        assert_eq!(tx.fee, MIN_TX_FEE);
        assert!(tx.recipient.is_none());
        assert!(tx.amount.is_none());

        // Verify the signature.
        let msg = tx.compute_signing_message().unwrap();
        assert!(pk.verify(&msg, &tx.publisher_sig).is_ok());
    }

    #[test]
    fn build_transfer_valid() {
        let (ks, sender) = setup_keystore();
        // Create a recipient key (just need the public key).
        let (_, recipient_bytes) = noble_crypto::ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recipient_bytes);

        let tx = TransactionBuilder::build_transfer(
            &ks,
            &sender,
            recipient.clone(),
            500_000,
            MIN_TX_FEE,
            None,
        )
        .unwrap();

        assert_eq!(tx.tx_type, TX_TYPE_TRANSFER);
        assert_eq!(tx.recipient.as_ref().unwrap(), &recipient);
        assert_eq!(tx.amount, Some(500_000));
        assert_eq!(tx.checksum, Hash256::ZERO);

        // Verify the signature.
        let msg = tx.compute_signing_message().unwrap();
        assert!(sender.verify(&msg, &tx.publisher_sig).is_ok());
    }

    #[test]
    fn build_transfer_zero_amount_rejected() {
        let (ks, sender) = setup_keystore();
        let (_, recipient_bytes) = noble_crypto::ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recipient_bytes);

        let result =
            TransactionBuilder::build_transfer(&ks, &sender, recipient, 0, MIN_TX_FEE, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            WalletError::InvalidRecipient(msg) => {
                assert!(msg.contains("amount"), "error should mention amount: {msg}");
            }
            other => panic!("expected InvalidRecipient, got: {other}"),
        }
    }

    #[test]
    fn build_transfer_with_memo() {
        let (ks, sender) = setup_keystore();
        let (_, recipient_bytes) = noble_crypto::ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recipient_bytes);

        let tx = TransactionBuilder::build_transfer(
            &ks,
            &sender,
            recipient,
            100_000,
            MIN_TX_FEE,
            Some("payment for services".into()),
        )
        .unwrap();

        assert_eq!(tx.metadata.len(), 1);
        assert_eq!(tx.metadata[0].key, "memo");
        assert_eq!(
            String::from_utf8(tx.metadata[0].value.clone()).unwrap(),
            "payment for services"
        );
    }

    #[test]
    fn estimate_fee_returns_triple() {
        let (low, med, high) = TransactionBuilder::estimate_fee();
        assert_eq!(low, MIN_TX_FEE);
        assert_eq!(med, MIN_TX_FEE * 2);
        assert_eq!(high, MIN_TX_FEE * 5);
        assert!(low < med);
        assert!(med < high);
    }
}
