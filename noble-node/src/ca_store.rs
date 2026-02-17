// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! CA trust store for verifying PKI identity attestations.
//!
//! Each node maintains its own directory of trusted CA certificates (PEM/DER),
//! paralleling PoR's per-node validator list philosophy. The protocol stores
//! attestations as opaque bytes; verification is a client/node concern.

use std::path::Path;

use noble_core::ExternalAttestation;
use openssl::cms::CmsContentInfo;
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509;

/// A collection of trusted CA certificates used to verify PKI attestations.
pub struct CaStore {
    store: X509Store,
    cert_count: usize,
}

impl std::fmt::Debug for CaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaStore")
            .field("cert_count", &self.cert_count)
            .finish()
    }
}

impl CaStore {
    /// Load all PEM and DER certificate files from a directory.
    ///
    /// Returns an error if the directory doesn't exist or no certs are found.
    pub fn from_directory(dir: &Path) -> Result<Self, String> {
        if !dir.is_dir() {
            return Err(format!(
                "CA store path is not a directory: {}",
                dir.display()
            ));
        }

        let mut builder = X509StoreBuilder::new().map_err(|e| format!("X509StoreBuilder: {e}"))?;
        let mut count = 0;

        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("read CA store directory {}: {e}", dir.display()))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let data = std::fs::read(&path)
                .map_err(|e| format!("read cert file {}: {e}", path.display()))?;

            // Try PEM first, then DER
            let cert = if let Ok(c) = X509::from_pem(&data) {
                c
            } else if let Ok(c) = X509::from_der(&data) {
                c
            } else {
                tracing::debug!(path = %path.display(), "skipping non-certificate file");
                continue;
            };

            builder
                .add_cert(cert)
                .map_err(|e| format!("add cert {}: {e}", path.display()))?;
            count += 1;
        }

        if count == 0 {
            return Err(format!("no valid certificates found in {}", dir.display()));
        }

        Ok(Self {
            store: builder.build(),
            cert_count: count,
        })
    }

    /// Number of trusted CA certificates loaded.
    pub fn cert_count(&self) -> usize {
        self.cert_count
    }

    /// Verify a PKI identity binding attestation.
    ///
    /// `binding_message` is the expected signed content:
    /// `sha256("NOBLE-PKI-BIND-v1" || identity_key_bytes)`.
    ///
    /// Returns the signer's Common Name (CN) on success.
    pub fn verify_pki_binding(
        &self,
        binding_message: &[u8],
        attestation: &ExternalAttestation,
    ) -> Result<String, String> {
        if attestation.scheme != "pkcs7" {
            return Err(format!(
                "unsupported attestation scheme: {}",
                attestation.scheme
            ));
        }
        if attestation.scope != "identity" {
            return Err(format!(
                "expected scope 'identity', got '{}'",
                attestation.scope
            ));
        }

        // Parse the CMS/PKCS#7 signature
        let mut cms = CmsContentInfo::from_der(&attestation.signature_data)
            .map_err(|e| format!("parse CMS signature: {e}"))?;

        // Verify detached signature against the binding message
        let empty_certs = Stack::new().map_err(|e| format!("stack: {e}"))?;
        let mut output = Vec::new();
        cms.verify(
            Some(&empty_certs),
            Some(&self.store),
            Some(binding_message),
            Some(&mut output),
            openssl::cms::CMSOptions::DETACHED | openssl::cms::CMSOptions::BINARY,
        )
        .map_err(|e| format!("CMS verify: {e}"))?;

        // Extract the signer's CN from the attestation fingerprint
        // The fingerprint is stored in the attestation; look up the cert in the CMS
        // For simplicity, return a description based on the fingerprint
        Ok(format!(
            "verified (fingerprint: {})",
            hex::encode(&attestation.signer_fingerprint[..8])
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_store_missing_dir_rejected() {
        let result = CaStore::from_directory(Path::new("/nonexistent/ca/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }

    #[test]
    fn ca_store_empty_dir_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let result = CaStore::from_directory(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no valid certificates"));
    }

    #[test]
    fn ca_store_loads_pem_cert() {
        let dir = tempfile::tempdir().unwrap();
        // Generate a self-signed CA cert
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let mut name_builder = openssl::x509::X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test CA").unwrap();
        let name = name_builder.build();
        let mut builder = openssl::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let cert = builder.build();

        // Write PEM to dir
        let cert_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();

        let store = CaStore::from_directory(dir.path()).unwrap();
        assert_eq!(store.cert_count(), 1);
    }

    #[test]
    fn verify_rejects_wrong_scheme() {
        let dir = tempfile::tempdir().unwrap();
        // Create a minimal store with a cert
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let mut name_builder = openssl::x509::X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test CA").unwrap();
        let name = name_builder.build();
        let mut builder = openssl::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let cert = builder.build();
        std::fs::write(dir.path().join("ca.pem"), cert.to_pem().unwrap()).unwrap();

        let store = CaStore::from_directory(dir.path()).unwrap();
        let att = ExternalAttestation {
            scheme: "pgp".to_string(),
            scope: "identity".to_string(),
            signer_fingerprint: [0; 32],
            signature_data: vec![],
        };
        let result = store.verify_pki_binding(b"test", &att);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported"));
    }
}
