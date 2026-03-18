// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! One-time PKCS#12 loading and PKI identity binding.
//!
//! Loads a `.p12` file, creates a CMS detached signature over a stable
//! binding message (`sha256("NOBLE-PKI-BIND-v1" || identity_key_bytes)`),
//! and saves the resulting attestation to disk. On subsequent startups
//! the saved attestation is loaded and the `.p12` file is no longer needed.

use std::path::Path;

use noble_core::{compute_pki_binding_message_for_key, ExternalAttestation};
use noble_crypto::NoblePublicKey;
use openssl::cms::CmsContentInfo;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;

/// Loaded PKCS#12 identity — private key + certificate chain.
pub struct Pkcs12Identity {
    pkey: PKey<openssl::pkey::Private>,
    cert: X509,
}

impl Pkcs12Identity {
    /// Load a PKCS#12 file from disk.
    pub fn from_file(path: &Path, password: &str) -> Result<Self, String> {
        let data =
            std::fs::read(path).map_err(|e| format!("read .p12 file {}: {e}", path.display()))?;
        let pkcs12 = Pkcs12::from_der(&data).map_err(|e| format!("parse PKCS#12: {e}"))?;
        let parsed = pkcs12
            .parse2(password)
            .map_err(|e| format!("decrypt PKCS#12 (wrong password?): {e}"))?;

        let pkey = parsed
            .pkey
            .ok_or_else(|| "PKCS#12 file contains no private key".to_string())?;
        let cert = parsed
            .cert
            .ok_or_else(|| "PKCS#12 file contains no certificate".to_string())?;

        Ok(Self { pkey, cert })
    }

    /// Create a CMS detached signature binding the NOBLE identity key to
    /// this X.509 certificate.
    ///
    /// The signed content is: `sha256("NOBLE-PKI-BIND-v1" || identity_key_bytes)`.
    pub fn sign_pki_binding(
        &self,
        identity_key: &NoblePublicKey,
    ) -> Result<ExternalAttestation, String> {
        let binding_msg = compute_pki_binding_message_for_key(identity_key);

        // Create CMS detached signature
        let cms = CmsContentInfo::sign(
            Some(&self.cert),
            Some(&self.pkey),
            None, // no additional certs in chain
            Some(&binding_msg),
            openssl::cms::CMSOptions::DETACHED | openssl::cms::CMSOptions::BINARY,
        )
        .map_err(|e| format!("CMS sign: {e}"))?;

        let signature_data = cms.to_der().map_err(|e| format!("CMS to DER: {e}"))?;

        // Compute SHA-256 fingerprint of the signer's certificate
        let fingerprint_bytes = self
            .cert
            .digest(MessageDigest::sha256())
            .map_err(|e| format!("cert fingerprint: {e}"))?;
        let mut signer_fingerprint = [0u8; 32];
        signer_fingerprint.copy_from_slice(&fingerprint_bytes);

        Ok(ExternalAttestation {
            scheme: "pkcs7".to_string(),
            scope: "identity".to_string(),
            signer_fingerprint,
            signature_data,
        })
    }

    /// Get the Common Name (CN) from the certificate subject.
    pub fn subject_cn(&self) -> Option<String> {
        self.cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok().map(|s| s.to_string()))
    }
}

/// Save an attestation to disk as encrypted CBOR (Noble envelope).
pub fn save_attestation(
    path: &Path,
    attestation: &ExternalAttestation,
    chain_meta: &[u8; 32],
) -> Result<(), String> {
    use noble_codec::NobleCbor;
    let cbor_bytes = attestation
        .to_cbor()
        .map_err(|e| format!("serialize attestation: {e}"))?;
    let encrypted = noble_crypto::file_encrypt::encrypt_file_data(&cbor_bytes, chain_meta)
        .map_err(|e| format!("encrypt attestation: {e}"))?;
    std::fs::write(path, &encrypted)
        .map_err(|e| format!("write attestation to {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Load a saved attestation from disk (supports encrypted Noble envelope and legacy plaintext CBOR).
pub fn load_attestation(
    path: &Path,
    chain_meta: &[u8; 32],
) -> Result<ExternalAttestation, String> {
    use noble_codec::NobleCbor;
    let file_bytes = std::fs::read(path)
        .map_err(|e| format!("read attestation from {}: {e}", path.display()))?;
    let cbor_bytes = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
        let (decrypted, migrated) = noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, chain_meta)
            .map_err(|e| format!("decrypt attestation: {e}"))?;
        if migrated {
            if let Ok(re_encrypted) = noble_crypto::file_encrypt::encrypt_file_data(&decrypted, chain_meta) {
                let _ = std::fs::write(path, &re_encrypted);
            }
            tracing::info!(task = "key_migration", "Migrated attestation to current encryption key");
        }
        decrypted
    } else {
        // Legacy plaintext CBOR — migrate in place.
        if let Ok(encrypted) =
            noble_crypto::file_encrypt::encrypt_file_data(&file_bytes, chain_meta)
        {
            if std::fs::write(path, &encrypted).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
        file_bytes
    };
    ExternalAttestation::from_cbor(&cbor_bytes).map_err(|e| format!("deserialize attestation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_pkcs12() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        // Generate an RSA key + self-signed cert
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let mut name_builder = openssl::x509::X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Node")
            .unwrap();
        name_builder.append_entry_by_text("O", "Test Org").unwrap();
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
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        // Build PKCS#12
        let pkcs12 = Pkcs12::builder()
            .name("test")
            .pkey(&pkey)
            .cert(&cert)
            .build2("testpass")
            .unwrap();
        let p12_path = dir.path().join("test.p12");
        std::fs::write(&p12_path, pkcs12.to_der().unwrap()).unwrap();
        (dir, p12_path)
    }

    #[test]
    fn load_pkcs12_and_sign_binding() {
        let (_dir, p12_path) = generate_test_pkcs12();
        let identity = Pkcs12Identity::from_file(&p12_path, "testpass").unwrap();
        assert_eq!(identity.subject_cn().as_deref(), Some("Test Node"));

        // Sign a binding for a test NOBLE key
        let (sk_bytes, _) = noble_crypto::secp256k1::generate_keypair();
        let sk = noble_crypto::NoblePrivateKey::Secp256k1(sk_bytes);
        let pk = sk.public_key();
        let att = identity.sign_pki_binding(&pk).unwrap();
        assert_eq!(att.scheme, "pkcs7");
        assert_eq!(att.scope, "identity");
        assert!(!att.signature_data.is_empty());
        assert_ne!(att.signer_fingerprint, [0u8; 32]);
    }

    #[test]
    fn save_and_load_attestation() {
        let dir = tempfile::tempdir().unwrap();
        let att = ExternalAttestation {
            scheme: "pkcs7".to_string(),
            scope: "identity".to_string(),
            signer_fingerprint: [0xAB; 32],
            signature_data: vec![1, 2, 3, 4],
        };
        let path = dir.path().join("attestation.cbor");
        save_attestation(&path, &att, &[0x42u8; 32]).unwrap();
        let loaded = load_attestation(&path, &[0x42u8; 32]).unwrap();
        assert_eq!(loaded.scheme, "pkcs7");
        assert_eq!(loaded.signer_fingerprint, [0xAB; 32]);
        assert_eq!(loaded.signature_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn wrong_password_rejected() {
        let (_dir, p12_path) = generate_test_pkcs12();
        let result = Pkcs12Identity::from_file(&p12_path, "wrongpass");
        assert!(result.is_err());
    }
}
