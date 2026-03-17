// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Locator decryption — recover the plaintext URL from an encrypted locator.

use noble_core::Transaction;
use noble_crypto::ecies::decrypt_as_recipient;
use noble_crypto::NoblePrivateKey;

use crate::error::WalletError;

/// Decrypt the encrypted locator in a transaction, recovering the plaintext URL.
///
/// Finds the recipient envelope matching the given private key's public key,
/// decrypts the data encryption key via ECIES, then decrypts the URL payload.
pub fn decrypt_locator(
    tx: &Transaction,
    private_key: &NoblePrivateKey,
) -> Result<Vec<u8>, WalletError> {
    let locator = tx
        .encrypted_locator
        .as_ref()
        .ok_or_else(|| WalletError::Crypto("transaction has no encrypted locator".into()))?;

    let our_pubkey = private_key.public_key();

    let envelope = locator
        .recipients
        .iter()
        .find(|r| r.recipient == our_pubkey)
        .ok_or_else(|| WalletError::Crypto("not a recipient of this locator".into()))?;

    // Decrypt the DEK using ECIES
    let dek = decrypt_as_recipient(
        private_key,
        &envelope.ephemeral_pubkey,
        &envelope.encrypted_key,
        &envelope.key_nonce,
    )?;

    // Decrypt the payload using the DEK
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new((&dek).into());
    let nonce = Nonce::from_slice(&locator.nonce);
    let plaintext = cipher
        .decrypt(nonce, locator.ciphertext.as_ref())
        .map_err(|e| WalletError::Crypto(format!("AES-GCM decrypt: {e}")))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::ExternalAttestation;
    use noble_crypto::{ed25519, sha256, NoblePublicKey, SCHEME_ED25519};
    use noble_test_utils::fixtures::test_chain_id;

    fn setup_keystore_and_build(
        url: &[u8],
        recipients: &[NoblePublicKey],
        attestations: Vec<ExternalAttestation>,
    ) -> Transaction {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = crate::keystore::KeyStore::new(dir.path().join("keys")).unwrap();
        ks.unlock("test-pass-long").unwrap();
        let signer = ks.create_key(SCHEME_ED25519, "test-pass-long").unwrap();

        let addr = noble_core::NobleAddress::Noble(signer.clone());
        let utxo = crate::builder::SelectedUtxo {
            outpoint: noble_core::OutPoint {
                txid: sha256(signer.key_bytes()),
                vout: 0,
            },
            value: 100_000,
        };
        crate::builder::TransactionBuilder::build_notarization_with_locator(
            &ks,
            &signer,
            sha256(b"document.pdf"),
            1_000,
            vec![],
            url,
            recipients,
            attestations,
            test_chain_id(),
            &[utxo],
            &addr,
        )
        .unwrap()
    }

    #[test]
    fn build_and_decrypt_locator_ed25519() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let url = b"https://example.com/document.pdf";
        let tx = setup_keystore_and_build(url, &[pub_key], vec![]);

        assert!(tx.encrypted_locator.is_some());
        let locator = tx.encrypted_locator.as_ref().unwrap();
        assert_eq!(locator.recipients.len(), 1);

        let decrypted = decrypt_locator(&tx, &priv_key).unwrap();
        assert_eq!(decrypted, url);
    }

    #[test]
    fn build_with_attestations_in_signing_payload() {
        let (_sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk);

        let attestation = ExternalAttestation {
            scheme: "pkcs7".into(),
            scope: "hash".into(),
            signer_fingerprint: [0xAA; 32],
            signature_data: vec![0u8; 128],
        };

        let url = b"ipfs://QmTest123";
        let tx = setup_keystore_and_build(url, &[pub_key], vec![attestation]);

        assert_eq!(tx.external_attestations.len(), 1);
        assert_eq!(tx.external_attestations[0].scheme, "pkcs7");

        // Verify the attestation is included in the signing payload
        // (changing it would invalidate the signature)
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert!(tx.issuer_sig.verify_standalone(&msg).is_ok());
    }

    #[test]
    fn decrypt_locator_recovers_url() {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk);

        let url = b"https://storage.example.com/docs/contract-v2.pdf";
        let tx = setup_keystore_and_build(url, &[pub_key], vec![]);

        let decrypted = decrypt_locator(&tx, &priv_key).unwrap();
        assert_eq!(decrypted, url);
    }

    #[test]
    fn decrypt_locator_wrong_key_fails() {
        let (_sk1, pk1) = ed25519::generate_keypair();
        let (sk2, _pk2) = ed25519::generate_keypair();

        let pub_key1 = NoblePublicKey::Ed25519(pk1);
        let priv_key2 = NoblePrivateKey::Ed25519(sk2);

        let url = b"https://secret.example.com/doc.pdf";
        let tx = setup_keystore_and_build(url, &[pub_key1], vec![]);

        let result = decrypt_locator(&tx, &priv_key2);
        assert!(result.is_err(), "wrong key must not decrypt locator");
    }
}
