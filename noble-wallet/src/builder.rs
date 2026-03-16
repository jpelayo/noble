// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder — constructs and signs notarization and transfer transactions
//! using the UTXO model (inputs/outputs).

use noble_core::{
    EncryptedLocator, ExternalAttestation, LocatorRecipient, MetadataEntry, NobleAddress,
    OutPoint, Transaction, TxIn, TxOut,
    MIN_TX_FEE, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION, TX_TYPE_TRANSFER,
};
use noble_crypto::ecies::{encrypt_for_recipient, EciesRecipient};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};

use crate::error::WalletError;
use crate::keystore::KeyStore;

/// A typed metadata slot for schema-aware notarization.
pub enum TypedSlot {
    Utf8 { label: String, value: String },
    Base64 { label: String, value: String },
    Hex { label: String, value: Vec<u8> },
    Der { label: String, value: Vec<u8> },
    Ecies { label: String, value: Vec<u8> },
    Raw { label: String, value: Vec<u8> },
}

impl TypedSlot {
    fn visibility(&self) -> &str {
        match self {
            Self::Ecies { .. } => "priv",
            _ => "pub",
        }
    }

    fn encoding(&self) -> &str {
        match self {
            Self::Utf8 { .. } => "utf8",
            Self::Base64 { .. } => "b64",
            Self::Hex { .. } => "hex",
            Self::Der { .. } => "der",
            Self::Ecies { .. } => "ecies",
            Self::Raw { .. } => "raw",
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Utf8 { label, .. }
            | Self::Base64 { label, .. }
            | Self::Hex { label, .. }
            | Self::Der { label, .. }
            | Self::Ecies { label, .. }
            | Self::Raw { label, .. } => label,
        }
    }

    fn to_metadata_entry(&self) -> MetadataEntry {
        let value = match self {
            Self::Utf8 { value, .. } => value.as_bytes().to_vec(),
            Self::Base64 { value, .. } => value.as_bytes().to_vec(),
            Self::Hex { value, .. } => value.clone(),
            Self::Der { value, .. } => value.clone(),
            Self::Ecies { value, .. } => value.clone(),
            Self::Raw { value, .. } => value.clone(),
        };
        MetadataEntry {
            key: self.label().to_string(),
            value,
        }
    }
}

/// A selected UTXO for spending in a transaction.
#[derive(Debug, Clone)]
pub struct SelectedUtxo {
    pub outpoint: OutPoint,
    pub value: u64,
}

/// Static-like namespace for building signed transactions.
pub struct TransactionBuilder;

impl TransactionBuilder {
    /// Build a signed notarization transaction (UTXO model).
    ///
    /// `utxos`: selected UTXOs to spend (must cover the fee).
    /// Fee = sum(utxo values) - sum(output values).
    pub fn build_notarization(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        checksum: Hash256,
        fee: u64,
        metadata: Vec<MetadataEntry>,
        chain_id: u32,
        utxos: &[SelectedUtxo],
        change_address: &NobleAddress,
    ) -> Result<Transaction, WalletError> {
        tracing::debug!(task = "wallet_build", "building notarization transaction");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let total_input: u64 = utxos.iter().map(|u| u.value).sum();
        if total_input < fee {
            return Err(WalletError::InsufficientFunds {
                available: total_input,
                required: fee,
            });
        }

        let inputs: Vec<TxIn> = utxos
            .iter()
            .map(|u| TxIn { prev_output: u.outpoint.clone() })
            .collect();

        let change = total_input - fee;
        let outputs = if change > 0 {
            vec![TxOut { value: change, address: change_address.clone() }]
        } else {
            vec![]
        };

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs,
            outputs,
            checksum,
            timestamp,
            publisher_sig: SignatureEnvelope {
                scheme_id: signer.scheme_id(),
                public_key: signer.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };

        let msg = tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        tracing::trace!(task = "wallet_build", "notarization built, fee: {}", fee);
        Ok(tx)
    }

    /// Build a signed transfer transaction (UTXO model).
    ///
    /// `utxos`: selected UTXOs to spend (must cover amount + fee).
    /// Creates recipient output + optional change output.
    pub fn build_transfer(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        recipient: NobleAddress,
        amount: u64,
        fee: u64,
        memo: Option<String>,
        chain_id: u32,
        utxos: &[SelectedUtxo],
        change_address: &NobleAddress,
    ) -> Result<Transaction, WalletError> {
        tracing::debug!(task = "wallet_build", "building transfer, amount: {}", amount);
        if amount == 0 {
            return Err(WalletError::InvalidRecipient("amount must be > 0".into()));
        }

        let total_input: u64 = utxos.iter().map(|u| u.value).sum();
        let required = amount + fee;
        if total_input < required {
            return Err(WalletError::InsufficientFunds {
                available: total_input,
                required,
            });
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut metadata = vec![];
        if let Some(m) = memo {
            metadata.push(MetadataEntry {
                key: "memo".into(),
                value: m.into_bytes(),
            });
        }

        let inputs: Vec<TxIn> = utxos
            .iter()
            .map(|u| TxIn { prev_output: u.outpoint.clone() })
            .collect();

        let change = total_input - amount - fee;
        let mut outputs = vec![TxOut { value: amount, address: recipient }];
        if change > 0 {
            outputs.push(TxOut { value: change, address: change_address.clone() });
        }

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs,
            outputs,
            checksum: Hash256::ZERO,
            timestamp,
            publisher_sig: SignatureEnvelope {
                scheme_id: signer.scheme_id(),
                public_key: signer.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };

        let msg = tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        tracing::trace!(task = "wallet_build", "transfer built, fee: {}", fee);
        Ok(tx)
    }

    /// Build a signed notarization with an encrypted locator (UTXO model).
    #[allow(clippy::too_many_arguments)]
    pub fn build_notarization_with_locator(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        checksum: Hash256,
        fee: u64,
        metadata: Vec<MetadataEntry>,
        url: &[u8],
        recipients: &[NoblePublicKey],
        attestations: Vec<ExternalAttestation>,
        chain_id: u32,
        utxos: &[SelectedUtxo],
        change_address: &NobleAddress,
    ) -> Result<Transaction, WalletError> {
        if recipients.is_empty() {
            return Err(WalletError::Crypto(
                "at least one locator recipient required".into(),
            ));
        }

        // Generate random data encryption key
        use rand::RngCore;
        let mut dek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek);

        // Encrypt URL with DEK using AES-256-GCM
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new((&dek).into());
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, url)
            .map_err(|e| WalletError::Crypto(format!("AES-GCM encrypt: {e}")))?;

        // Encrypt DEK for each recipient via ECIES
        let mut locator_recipients = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let envelope: EciesRecipient = encrypt_for_recipient(recipient, &dek)?;
            locator_recipients.push(LocatorRecipient {
                recipient: envelope.recipient_pubkey,
                ephemeral_pubkey: envelope.ephemeral_pubkey,
                encrypted_key: envelope.encrypted_key,
                key_nonce: envelope.key_nonce,
            });
        }

        let encrypted_locator = Some(EncryptedLocator {
            ciphertext,
            nonce: nonce_bytes,
            recipients: locator_recipients,
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let total_input: u64 = utxos.iter().map(|u| u.value).sum();
        if total_input < fee {
            return Err(WalletError::InsufficientFunds {
                available: total_input,
                required: fee,
            });
        }
        let inputs: Vec<TxIn> = utxos.iter().map(|u| TxIn { prev_output: u.outpoint.clone() }).collect();
        let change = total_input - fee;
        let outputs = if change > 0 {
            vec![TxOut { value: change, address: change_address.clone() }]
        } else {
            vec![]
        };

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs,
            outputs,
            checksum,
            timestamp,
            publisher_sig: SignatureEnvelope {
                scheme_id: signer.scheme_id(),
                public_key: signer.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator,
            external_attestations: attestations,
            gateway_address: None,
        contract_data: None,
        };

        let msg = tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(tx)
    }

    /// Build a signed notarization with auto-generated schema descriptor (UTXO model).
    pub fn build_notarization_with_schema(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        checksum: Hash256,
        fee: u64,
        slots: Vec<TypedSlot>,
        chain_id: u32,
        utxos: &[SelectedUtxo],
        change_address: &NobleAddress,
    ) -> Result<Transaction, WalletError> {
        let mut lines = vec!["0:pub:utf8:opt:schema".to_string()];
        for (i, slot) in slots.iter().enumerate() {
            lines.push(format!(
                "{}:{}:{}:opt:{}",
                i + 1,
                slot.visibility(),
                slot.encoding(),
                slot.label(),
            ));
        }
        let schema_value = lines.join("\n");

        let mut metadata = Vec::with_capacity(1 + slots.len());
        metadata.push(MetadataEntry {
            key: "schema".into(),
            value: schema_value.into_bytes(),
        });
        for slot in &slots {
            metadata.push(slot.to_metadata_entry());
        }

        Self::build_notarization(keystore, signer, checksum, fee, metadata, chain_id, utxos, change_address)
    }

    /// Set the gateway address on an already-built transaction and re-sign.
    pub fn set_gateway_and_resign(
        tx: &mut Transaction,
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        gateway: Vec<u8>,
        chain_id: u32,
    ) -> Result<(), WalletError> {
        tx.gateway_address = Some(gateway);
        let msg = tx
            .compute_signing_message_for_chain(chain_id)
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(())
    }

    /// Estimate fee based on mempool fullness (placeholder).
    pub fn estimate_fee() -> (u64, u64, u64) {
        (MIN_TX_FEE, MIN_TX_FEE * 2, MIN_TX_FEE * 5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{sha256, SCHEME_ED25519};
    use noble_test_utils::fixtures::test_chain_id;
    use tempfile::tempdir;

    fn setup_keystore() -> (crate::keystore::KeyStore, NoblePublicKey) {
        let dir = tempdir().unwrap();
        let mut ks = crate::keystore::KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("test-pass-long").unwrap();
        let pk = ks.create_key(SCHEME_ED25519, "test-pass-long").unwrap();
        (ks, pk)
    }

    fn make_test_utxos(pk: &NoblePublicKey, value: u64) -> (Vec<SelectedUtxo>, NobleAddress) {
        let addr = NobleAddress::Noble(pk.clone());
        let outpoint = OutPoint {
            txid: sha256(pk.key_bytes()),
            vout: 0,
        };
        (vec![SelectedUtxo { outpoint, value }], addr)
    }

    #[test]
    fn build_notarization_valid() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xAB; 32]);
        let (utxos, addr) = make_test_utxos(&pk, 100_000);
        let tx = TransactionBuilder::build_notarization(
            &ks, &pk, checksum, MIN_TX_FEE, vec![], test_chain_id(), &utxos, &addr,
        ).unwrap();

        assert_eq!(tx.version, PROTOCOL_VERSION);
        assert_eq!(tx.tx_type, TX_TYPE_NOTARIZATION);
        assert_eq!(tx.checksum, checksum);
        assert_eq!(tx.inputs.len(), 1);
        // Change output: 100_000 - MIN_TX_FEE
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 100_000 - MIN_TX_FEE);

        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert!(pk.verify(&msg, &tx.publisher_sig).is_ok());
    }

    #[test]
    fn build_transfer_valid() {
        let (ks, sender_pk) = setup_keystore();
        let (_, recipient_bytes) = noble_crypto::ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recipient_bytes);
        let recipient_addr = NobleAddress::Noble(recipient.clone());

        let (utxos, change_addr) = make_test_utxos(&sender_pk, 1_000_000);
        let tx = TransactionBuilder::build_transfer(
            &ks, &sender_pk, recipient_addr, 500_000, MIN_TX_FEE,
            None, test_chain_id(), &utxos, &change_addr,
        ).unwrap();

        assert_eq!(tx.tx_type, TX_TYPE_TRANSFER);
        assert_eq!(tx.outputs[0].value, 500_000); // recipient
        assert!(tx.outputs.len() >= 2); // + change
        assert_eq!(tx.checksum, Hash256::ZERO);

        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert!(sender_pk.verify(&msg, &tx.publisher_sig).is_ok());
    }

    #[test]
    fn build_transfer_zero_amount_rejected() {
        let (ks, sender_pk) = setup_keystore();
        let (_, rb) = noble_crypto::ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(rb));
        let (utxos, addr) = make_test_utxos(&sender_pk, 1_000_000);

        let result = TransactionBuilder::build_transfer(
            &ks, &sender_pk, recipient, 0, MIN_TX_FEE,
            None, test_chain_id(), &utxos, &addr,
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_transfer_insufficient_funds() {
        let (ks, sender_pk) = setup_keystore();
        let (_, rb) = noble_crypto::ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(rb));
        let (utxos, addr) = make_test_utxos(&sender_pk, 100); // only 100 atomic

        let result = TransactionBuilder::build_transfer(
            &ks, &sender_pk, recipient, 500_000, MIN_TX_FEE,
            None, test_chain_id(), &utxos, &addr,
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_transfer_with_memo() {
        let (ks, sender_pk) = setup_keystore();
        let (_, rb) = noble_crypto::ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(rb));
        let (utxos, addr) = make_test_utxos(&sender_pk, 1_000_000);

        let tx = TransactionBuilder::build_transfer(
            &ks, &sender_pk, recipient, 100_000, MIN_TX_FEE,
            Some("payment for services".into()), test_chain_id(), &utxos, &addr,
        ).unwrap();

        assert_eq!(tx.metadata.len(), 1);
        assert_eq!(tx.metadata[0].key, "memo");
    }

    #[test]
    fn estimate_fee_returns_triple() {
        let (low, med, high) = TransactionBuilder::estimate_fee();
        assert!(low < med && med < high);
    }

    #[test]
    fn set_gateway_and_resign_updates_field_and_signature() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xAB; 32]);
        let (utxos, addr) = make_test_utxos(&pk, 100_000);
        let mut tx = TransactionBuilder::build_notarization(
            &ks, &pk, checksum, MIN_TX_FEE, vec![], test_chain_id(), &utxos, &addr,
        ).unwrap();

        let msg_before = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();

        let (_, gw_pk) = noble_crypto::ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk);
        let gw_wire = gw_key.to_wire_bytes();

        TransactionBuilder::set_gateway_and_resign(&mut tx, &ks, &pk, gw_wire, test_chain_id()).unwrap();

        let msg_after = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert_ne!(msg_before, msg_after);
        assert!(pk.verify(&msg_after, &tx.publisher_sig).is_ok());
    }
}
