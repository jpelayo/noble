// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder — constructs and signs notarization and transfer transactions.

use noble_core::{
    EncryptedLocator, ExternalAttestation, LocatorRecipient, MetadataEntry, Transaction,
    MIN_TX_FEE, PROTOCOL_VERSION, TX_TYPE_NOTARIZATION, TX_TYPE_TRANSFER,
};
use noble_crypto::ecies::{encrypt_for_recipient, EciesRecipient};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};

use crate::error::WalletError;
use crate::keystore::KeyStore;

/// A typed metadata slot for schema-aware notarization.
///
/// Each variant carries its data and a label string.  The builder uses
/// these to auto-generate the slot-0 schema descriptor.
pub enum TypedSlot {
    /// UTF-8 plaintext (visibility: public).
    Utf8 { label: String, value: String },
    /// Base64-encoded text (visibility: public).
    Base64 { label: String, value: String },
    /// Raw hex bytes (visibility: public).
    Hex { label: String, value: Vec<u8> },
    /// DER-encoded certificate (visibility: public).
    Der { label: String, value: Vec<u8> },
    /// ECIES-encrypted data (visibility: private).  The builder stores the
    /// *already-encrypted* bytes — encryption is the caller's responsibility.
    Ecies { label: String, value: Vec<u8> },
    /// Opaque raw bytes (visibility: public).
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
            encrypted_locator: None,
            external_attestations: vec![],
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
            encrypted_locator: None,
            external_attestations: vec![],
        };

        let msg = tx
            .compute_signing_message()
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(tx)
    }

    /// Build a signed notarization transaction with an encrypted locator.
    ///
    /// The `url` is encrypted for each recipient using hybrid ECIES.
    /// Optionally includes external attestations (opaque signatures from non-NOBLE PKI).
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
            encrypted_locator,
            external_attestations: attestations,
        };

        let msg = tx
            .compute_signing_message()
            .map_err(|e| WalletError::Crypto(e.to_string()))?;
        tx.publisher_sig = keystore.sign(signer, &msg)?;
        Ok(tx)
    }

    /// Build a signed notarization with auto-generated schema descriptor.
    ///
    /// Slot 0 is reserved for the schema descriptor (generated automatically
    /// from the provided `TypedSlot` definitions).  User-provided slots start
    /// at index 1.
    pub fn build_notarization_with_schema(
        keystore: &KeyStore,
        signer: &NoblePublicKey,
        checksum: Hash256,
        fee: u64,
        slots: Vec<TypedSlot>,
    ) -> Result<Transaction, WalletError> {
        // Build the schema descriptor lines.  Slot 0 is always the schema
        // itself; user slots are numbered 1..=N.
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

        // Assemble metadata: slot 0 = schema descriptor, then user slots.
        let mut metadata = Vec::with_capacity(1 + slots.len());
        metadata.push(MetadataEntry {
            key: "schema".into(),
            value: schema_value.into_bytes(),
        });
        for slot in &slots {
            metadata.push(slot.to_metadata_entry());
        }

        Self::build_notarization(keystore, signer, checksum, fee, metadata)
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

    #[test]
    fn build_with_schema_produces_valid_descriptor() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xCC; 32]);
        let slots = vec![
            TypedSlot::Utf8 {
                label: "description".into(),
                value: "Certificate of Completion".into(),
            },
            TypedSlot::Hex {
                label: "fingerprint".into(),
                value: vec![0xAB; 32],
            },
        ];

        let tx = TransactionBuilder::build_notarization_with_schema(
            &ks, &pk, checksum, MIN_TX_FEE, slots,
        )
        .unwrap();

        // Slot 0 must be the schema descriptor.
        assert_eq!(tx.metadata.len(), 3);
        assert_eq!(tx.metadata[0].key, "schema");

        let schema_text = String::from_utf8(tx.metadata[0].value.clone()).unwrap();
        assert!(schema_text.contains("0:pub:utf8:opt:schema"));
        assert!(schema_text.contains("1:pub:utf8:opt:description"));
        assert!(schema_text.contains("2:pub:hex:opt:fingerprint"));
    }

    #[test]
    fn schema_descriptor_matches_slot_count_and_types() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xDD; 32]);
        let slots = vec![
            TypedSlot::Base64 {
                label: "doc_summary".into(),
                value: "SGVsbG8gV29ybGQ=".into(),
            },
            TypedSlot::Der {
                label: "cert_pubkey".into(),
                value: vec![0x30; 64],
            },
            TypedSlot::Ecies {
                label: "secret_url".into(),
                value: vec![0xFF; 48],
            },
        ];

        let tx = TransactionBuilder::build_notarization_with_schema(
            &ks, &pk, checksum, MIN_TX_FEE, slots,
        )
        .unwrap();

        // 1 schema + 3 user slots = 4 metadata entries.
        assert_eq!(tx.metadata.len(), 4);

        let schema_text = String::from_utf8(tx.metadata[0].value.clone()).unwrap();
        let lines: Vec<&str> = schema_text.lines().collect();
        // 4 lines: schema + 3 user slots.
        assert_eq!(lines.len(), 4);
        assert!(lines[1].contains("b64"));
        assert!(lines[1].contains("doc_summary"));
        assert!(lines[2].contains("der"));
        assert!(lines[2].contains("cert_pubkey"));
        assert!(lines[3].contains("ecies"));
        assert!(lines[3].contains("priv"));
        assert!(lines[3].contains("secret_url"));
    }

    #[test]
    fn schema_roundtrip_types_match() {
        let (ks, pk) = setup_keystore();
        let checksum = Hash256::from_bytes([0xEE; 32]);
        let original_desc = "Test document #42";
        let slots = vec![TypedSlot::Utf8 {
            label: "description".into(),
            value: original_desc.into(),
        }];

        let tx = TransactionBuilder::build_notarization_with_schema(
            &ks, &pk, checksum, MIN_TX_FEE, slots,
        )
        .unwrap();

        // Verify the signature is valid.
        let msg = tx.compute_signing_message().unwrap();
        assert!(pk.verify(&msg, &tx.publisher_sig).is_ok());

        // Parse the schema back from metadata.
        let schema_text = String::from_utf8(tx.metadata[0].value.clone()).unwrap();
        let lines: Vec<&str> = schema_text.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify slot 1 value matches original.
        let desc_value = String::from_utf8(tx.metadata[1].value.clone()).unwrap();
        assert_eq!(desc_value, original_desc);
    }
}
