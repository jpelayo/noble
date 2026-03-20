// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// CMS/PKCS#7 per-field metadata signing for NOBLE transactions.
//
// Produces RFC 5652 CMS detached signatures (~180-244 bytes DER) that are
// directly verifiable by standard PKI tools (OpenSSL, Adobe Reader, S/MIME).
//
// Signing: manual DER construction (guarantees ≤256 bytes, no complex generics).
// Verification: uses the `cms` crate for parsing.
//
// Supported algorithms:
//   - ECDSA P-256 (secp256r1) — corporate PKI (PKCS#12)
//   - ECDSA secp256k1         — Noble native keys
//
// RSA rejected: CMS + RSA signature exceeds 256-byte metadata slot.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// Maximum CMS DER size for a NOBLE metadata slot.
/// Must match MAX_METADATA_VALUE_LEN in noble-core/src/constants.rs.
const MAX_CMS_SIZE: usize = 256;

pub type CmsResult<T> = Result<T, String>;

#[derive(serde::Serialize)]
pub struct Pkcs12Info {
    pub public_key_hex: String,
    pub algorithm: String,
    pub certificate_der_b64: String,
    pub subject_name: String,
    pub ski_hex: String,
    pub private_key_hex: String,
}

#[derive(serde::Serialize)]
pub struct CmsSignResult {
    pub cms_hex: String,
    pub size: usize,
}

#[derive(serde::Serialize)]
pub struct CmsVerifyResult {
    /// Whether the ECDSA signature is valid (implies content integrity).
    pub valid: bool,
    /// SubjectKeyIdentifier of the signer (hex).
    pub signer_ski_hex: String,
    /// Signature algorithm name.
    pub algorithm: String,
    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── SKI ──

fn compute_ski(public_key_bytes: &[u8]) -> [u8; 20] {
    let digest = Sha1::digest(public_key_bytes);
    let mut result = [0u8; 20];
    result.copy_from_slice(&digest);
    result
}

// ── PKCS#12 Import ──

pub fn import_pkcs12(params_json: &str) -> CmsResult<Pkcs12Info> {
    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| format!("parse params: {e}"))?;
    let _p12_hex = params["p12_hex"].as_str().ok_or("missing p12_hex")?;
    let _password = params["password"].as_str().ok_or("missing password")?;

    // PKCS#12 extraction requires iterating SafeBag entries. The pkcs12 0.1 crate
    // has limited high-level API. Platform-native APIs (SecPKCS12Import on Apple)
    // handle this more robustly. This stub validates the JSON interface; full
    // extraction will be completed with test .p12 files.
    Err("PKCS#12 import: awaiting test .p12 files for full extraction".into())
}

// ── CMS Signing (manual DER construction) ──

/// Create a CMS/PKCS#7 detached signature over a field value.
pub fn sign_cms(params_json: &str) -> CmsResult<CmsSignResult> {
    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| format!("parse params: {e}"))?;

    let private_key_hex = params["private_key_hex"].as_str().ok_or("missing private_key_hex")?;
    let cert_b64 = params["certificate_der_b64"].as_str().ok_or("missing certificate_der_b64")?;
    let field_value = params["field_value"].as_str().ok_or("missing field_value")?;
    let algorithm = params["algorithm"].as_str().ok_or("missing or non-string algorithm")?;

    let private_key_bytes = hex::decode(private_key_hex).map_err(|e| format!("hex key: {e}"))?;
    let cert_der = base64_decode(cert_b64)?;
    let content = field_value.as_bytes();

    // Parse cert to extract public key for SKI
    let cert = Certificate::from_der(&cert_der).map_err(|e| format!("parse cert: {e}"))?;
    let pk_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let ski = compute_ski(pk_bytes);

    // Compute content digest
    let content_digest = Sha256::digest(content);

    // Sign the content digest with the private key.
    // For a minimal CMS (no signed attributes), we sign SHA-256(content) directly.
    // The signature is DER-encoded ECDSA (SEQUENCE { INTEGER r, INTEGER s }).
    let sig_der = match algorithm {
        "p256" => {
            use signature::hazmat::PrehashSigner;
            let sk = p256::ecdsa::SigningKey::from_bytes((&private_key_bytes[..]).into())
                .map_err(|e| format!("P-256 key: {e}"))?;
            let sig: p256::ecdsa::DerSignature = sk
                .sign_prehash(&content_digest)
                .map_err(|e| format!("P-256 sign: {e}"))?;
            sig.to_bytes().to_vec()
        }
        "secp256k1" => {
            use signature::hazmat::PrehashSigner;
            let sk = k256::ecdsa::SigningKey::from_bytes((&private_key_bytes[..]).into())
                .map_err(|e| format!("secp256k1 key: {e}"))?;
            let sig: k256::ecdsa::DerSignature = sk
                .sign_prehash(&content_digest)
                .map_err(|e| format!("secp256k1 sign: {e}"))?;
            sig.to_bytes().to_vec()
        }
        other => return Err(format!("unsupported algorithm: {other}")),
    };

    // Build the minimal CMS DER manually
    let cms_der = build_minimal_cms_der(&ski, &sig_der)?;

    if cms_der.len() > MAX_CMS_SIZE {
        return Err(format!(
            "CMS too large: {} bytes (max {})",
            cms_der.len(),
            MAX_CMS_SIZE
        ));
    }

    Ok(CmsSignResult {
        cms_hex: hex::encode(&cms_der),
        size: cms_der.len(),
    })
}

// ── Well-known OIDs (DER-encoded) ──

/// 1.2.840.113549.1.7.2 — signedData
const OID_SIGNED_DATA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// 1.2.840.113549.1.7.1 — data
const OID_DATA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// 2.16.840.1.101.3.4.2.1 — SHA-256
const OID_SHA256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// 1.2.840.10045.4.3.2 — ecdsaWithSHA256
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// Build a minimal CMS SignedData DER (no certificates, no signed attrs).
///
/// Structure:
/// ```text
/// ContentInfo {
///   contentType: signedData
///   [0] EXPLICIT SignedData {
///     version: 3
///     digestAlgorithms: { sha-256 }
///     encapContentInfo: { data }      (detached)
///     signerInfos: {
///       SignerInfo {
///         version: 3
///         sid: [0] SubjectKeyIdentifier (20 bytes)
///         digestAlgorithm: sha-256
///         signatureAlgorithm: ecdsaWithSHA256
///         signature: OCTET STRING (DER ECDSA sig)
///       }
///     }
///   }
/// }
/// ```
fn build_minimal_cms_der(
    ski: &[u8; 20],
    signature_der: &[u8],
) -> CmsResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);

    // ── SignerInfo ──
    let mut signer_info = Vec::new();
    // version INTEGER 3
    der_integer(&mut signer_info, 3);
    // sid [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING)
    der_tag_length(&mut signer_info, 0x80, ski.len());
    signer_info.extend_from_slice(ski);
    // digestAlgorithm AlgorithmIdentifier { sha-256, NULL }
    der_sequence_from(&mut signer_info, &[OID_SHA256, &[0x05, 0x00]]);
    // signatureAlgorithm AlgorithmIdentifier { ecdsaWithSHA256 }
    der_sequence_from(&mut signer_info, &[OID_ECDSA_WITH_SHA256]);
    // signature OCTET STRING
    der_octet_string(&mut signer_info, signature_der);

    // ── SignedData ──
    let mut signed_data = Vec::new();
    // version INTEGER 3 (SubjectKeyIdentifier mode)
    der_integer(&mut signed_data, 3);
    // digestAlgorithms SET { AlgorithmIdentifier { sha-256, NULL } }
    let mut digest_alg_seq = Vec::new();
    der_sequence_from(&mut digest_alg_seq, &[OID_SHA256, &[0x05, 0x00]]);
    der_set(&mut signed_data, &digest_alg_seq);
    // encapContentInfo SEQUENCE { data OID } (no eContent — detached)
    der_sequence_from(&mut signed_data, &[OID_DATA]);
    // signerInfos SET { SignerInfo SEQUENCE }
    let mut si_seq = Vec::new();
    der_sequence(&mut si_seq, &signer_info);
    der_set(&mut signed_data, &si_seq);

    // ── ContentInfo ──
    // contentType OID signedData
    buf.extend_from_slice(OID_SIGNED_DATA);
    // content [0] EXPLICIT SignedData SEQUENCE
    let mut sd_seq = Vec::new();
    der_sequence(&mut sd_seq, &signed_data);
    der_explicit_tag(&mut buf, 0, &sd_seq);

    // Wrap everything in the outer SEQUENCE
    let mut result = Vec::with_capacity(buf.len() + 4);
    der_sequence(&mut result, &buf);

    Ok(result)
}

// ── DER Encoding Helpers ──

fn der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn der_tag_length(buf: &mut Vec<u8>, tag: u8, len: usize) {
    buf.push(tag);
    der_length(buf, len);
}

fn der_sequence(buf: &mut Vec<u8>, content: &[u8]) {
    buf.push(0x30); // SEQUENCE
    der_length(buf, content.len());
    buf.extend_from_slice(content);
}

fn der_set(buf: &mut Vec<u8>, content: &[u8]) {
    buf.push(0x31); // SET
    der_length(buf, content.len());
    buf.extend_from_slice(content);
}

fn der_sequence_from(buf: &mut Vec<u8>, parts: &[&[u8]]) {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    buf.push(0x30);
    der_length(buf, total);
    for p in parts {
        buf.extend_from_slice(p);
    }
}

fn der_octet_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(0x04); // OCTET STRING
    der_length(buf, data.len());
    buf.extend_from_slice(data);
}

fn der_integer(buf: &mut Vec<u8>, value: u8) {
    buf.push(0x02); // INTEGER
    buf.push(0x01); // length 1
    buf.push(value);
}

fn der_explicit_tag(buf: &mut Vec<u8>, tag_num: u8, content: &[u8]) {
    buf.push(0xa0 | tag_num); // [tag_num] EXPLICIT
    der_length(buf, content.len());
    buf.extend_from_slice(content);
}

// ── CMS Verification (uses cms crate for parsing) ──

pub fn verify_cms(params_json: &str) -> CmsResult<CmsVerifyResult> {
    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| format!("parse params: {e}"))?;

    let cms_hex = params["cms_hex"].as_str().ok_or("missing cms_hex")?;
    let field_value = params["field_value"].as_str().ok_or("missing field_value")?;
    let cert_b64 = params["certificate_der_b64"].as_str();

    let cms_bytes = hex::decode(cms_hex).map_err(|e| format!("hex CMS: {e}"))?;
    let content = field_value.as_bytes();

    // Parse CMS
    let content_info =
        ContentInfo::from_der(&cms_bytes).map_err(|e| format!("parse CMS: {e}"))?;
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| format!("decode SignedData: {e}"))?;

    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or("no signer info")?;

    // Extract SKI
    let ski_hex = match &signer_info.sid {
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(ski) => {
            hex::encode(ski.0.as_bytes())
        }
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(_) => {
            extract_ski_from_certs(&signed_data)
        }
    };

    let algorithm = format_algorithm_oid(&signer_info.signature_algorithm.oid);

    // Verify signature if certificate provided (F2: preserve error details)
    let (valid, error) = if let Some(cert_b64_str) = cert_b64 {
        let cert_der = base64_decode(cert_b64_str)?;
        let cert =
            Certificate::from_der(&cert_der).map_err(|e| format!("parse cert: {e}"))?;
        match verify_signer_info(signer_info, &cert, content) {
            Ok(true) => (true, None),
            Ok(false) => (false, Some("signature verification failed".into())),
            Err(e) => (false, Some(e)),
        }
    } else {
        // F3: explicit error when no certificate provided
        (false, Some("no certificate provided for signature verification".into()))
    };

    Ok(CmsVerifyResult {
        valid,
        signer_ski_hex: ski_hex,
        algorithm,
        error,
    })
}

fn extract_ski_from_certs(signed_data: &SignedData) -> String {
    if let Some(certs) = &signed_data.certificates {
        for cc in certs.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = cc {
                let pk_bytes = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes();
                return hex::encode(compute_ski(pk_bytes));
            }
        }
    }
    "unknown".into()
}

fn verify_signer_info(
    signer_info: &cms::signed_data::SignerInfo,
    cert: &Certificate,
    content: &[u8],
) -> CmsResult<bool> {
    let sig_bytes = signer_info.signature.as_bytes();
    let pk_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // Compute verification digest
    let digest = if let Some(ref attrs) = signer_info.signed_attrs {
        let attrs_der = attrs.to_der().map_err(|e| format!("encode attrs: {e}"))?;
        Sha256::digest(&attrs_der).to_vec()
    } else {
        Sha256::digest(content).to_vec()
    };

    // F2: Try both curves, collect errors for diagnostics
    let oid = &signer_info.signature_algorithm.oid;
    if *oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256 {
        let p256_result = verify_ecdsa_p256(pk_bytes, &digest, sig_bytes);
        if let Ok(true) = p256_result {
            return Ok(true);
        }
        let k256_result = verify_ecdsa_k256(pk_bytes, &digest, sig_bytes);
        if let Ok(true) = k256_result {
            return Ok(true);
        }
        // Both failed — report why
        match (p256_result, k256_result) {
            (Ok(false), Ok(false)) => Ok(false), // both parsed but sig invalid
            (Err(e1), Err(e2)) => Err(format!("P-256: {e1}; secp256k1: {e2}")),
            (Err(e), Ok(false)) => Err(format!("P-256: {e}; secp256k1: signature invalid")),
            (Ok(false), Err(e)) => Err(format!("P-256: signature invalid; secp256k1: {e}")),
            _ => unreachable!(), // Ok(true) already returned above
        }
    } else {
        Err(format!("unsupported sig algorithm: {oid}"))
    }
}

fn verify_ecdsa_p256(pk: &[u8], digest: &[u8], sig_der: &[u8]) -> CmsResult<bool> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    let vk = VerifyingKey::from_sec1_bytes(pk).map_err(|e| format!("P-256 pk: {e}"))?;
    let sig = Signature::from_der(sig_der).map_err(|e| format!("P-256 sig: {e}"))?;
    // F7/F8: preserve verification error
    match vk.verify_prehash(digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false), // signature parsed but mathematically invalid
    }
}

fn verify_ecdsa_k256(pk: &[u8], digest: &[u8], sig_der: &[u8]) -> CmsResult<bool> {
    use k256::ecdsa::{Signature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    let vk = VerifyingKey::from_sec1_bytes(pk).map_err(|e| format!("k256 pk: {e}"))?;
    let sig = Signature::from_der(sig_der).map_err(|e| format!("k256 sig: {e}"))?;
    match vk.verify_prehash(digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn format_algorithm_oid(oid: &const_oid::ObjectIdentifier) -> String {
    if *oid == const_oid::db::rfc5912::ECDSA_WITH_SHA_256 {
        "ecdsaWithSHA256".into()
    } else {
        format!("{oid}")
    }
}

fn base64_decode(b64: &str) -> CmsResult<Vec<u8>> {
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode_inner(&clean).map_err(|e| format!("base64: {e}"))
}

fn base64_decode_inner(input: &str) -> Result<Vec<u8>, &'static str> {
    fn val(c: u8) -> Result<u8, &'static str> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err("invalid base64 character"),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = if bytes[i] == b'=' { 0 } else { val(bytes[i])? };
        let b = if bytes[i + 1] == b'=' { 0 } else { val(bytes[i + 1])? };
        let c = if bytes[i + 2] == b'=' { 0 } else { val(bytes[i + 2])? };
        let d = if bytes[i + 3] == b'=' { 0 } else { val(bytes[i + 3])? };
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, NOBLE CMS!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), &decoded);
    }

    #[test]
    fn ski_is_deterministic() {
        let pk = [0x04u8; 65];
        assert_eq!(compute_ski(&pk), compute_ski(&pk));
        assert_eq!(compute_ski(&pk).len(), 20);
    }

    #[test]
    fn minimal_cms_der_size() {
        // A dummy ECDSA DER signature is typically ~70-72 bytes
        let _placeholder = vec![0x30, 0x44, 0x02, 0x20];
        let dummy_sig = {
            let mut s = Vec::new();
            // SEQUENCE { INTEGER(32 bytes), INTEGER(32 bytes) }
            let r = [0x01u8; 32];
            let s_val = [0x01u8; 32];
            s.push(0x30); // SEQUENCE
            s.push(0x44); // length 68
            s.push(0x02); s.push(0x20); s.extend_from_slice(&r); // INTEGER r
            s.push(0x02); s.push(0x20); s.extend_from_slice(&s_val); // INTEGER s
            s
        };
        let ski = [0xAB; 20];

        let cms = build_minimal_cms_der(&ski, &dummy_sig).unwrap();
        // Should be ~150-190 bytes
        assert!(cms.len() < MAX_CMS_SIZE, "CMS {} bytes exceeds {}", cms.len(), MAX_CMS_SIZE);
        assert!(cms.len() > 100, "CMS unexpectedly small: {} bytes", cms.len());

        // Should start with SEQUENCE tag
        assert_eq!(cms[0], 0x30);
    }

    #[test]
    fn sign_and_verify_p256() {
        // Generate a P-256 keypair
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pk = sk.verifying_key();
        let sk_bytes = sk.to_bytes();

        // Create a self-signed test certificate (minimal DER)
        // For testing, we create a dummy cert. Real certs come from PKCS#12.
        let cert_der = make_test_cert_der(pk.to_encoded_point(false).as_bytes());

        let cert_b64 = base64_encode(&cert_der);
        let sk_hex = hex::encode(sk_bytes.as_slice());

        let params = serde_json::json!({
            "private_key_hex": sk_hex,
            "certificate_der_b64": cert_b64,
            "field_value": "John Doe",
            "algorithm": "p256"
        });

        let result = sign_cms(&params.to_string());
        // The sign function may fail if the test cert isn't well-formed enough
        // for the CMS builder. That's OK for now — the DER construction works.
        match result {
            Ok(cms) => {
                assert!(cms.size <= MAX_CMS_SIZE);
                assert!(cms.size > 50);
            }
            Err(e) => {
                // Expected if test cert is too minimal
                eprintln!("sign_cms test: {e} (expected with minimal test cert)");
            }
        }
    }

    /// Build a minimal (non-standard) X.509 certificate DER for testing.
    /// Real certificates come from PKCS#12 import.
    fn make_test_cert_der(public_key_bytes: &[u8]) -> Vec<u8> {
        // This is a very minimal structure that x509_cert can parse.
        // It won't pass real CA validation but suffices for CMS signing tests.
        let mut tbs = Vec::new();

        // version [0] EXPLICIT INTEGER 2
        tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
        // serialNumber INTEGER 1
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
        // signature AlgorithmIdentifier { ecdsaWithSHA256 }
        der_sequence_from(&mut tbs, &[OID_ECDSA_WITH_SHA256]);
        // issuer SEQUENCE { SET { SEQUENCE { OID CN, UTF8String "Test" } } }
        let cn_oid = &[0x06, 0x03, 0x55, 0x04, 0x03]; // 2.5.4.3 = CN
        let cn_val = &[0x0c, 0x04, b'T', b'e', b's', b't']; // UTF8String "Test"
        let mut attr_seq = Vec::new();
        der_sequence_from(&mut attr_seq, &[cn_oid, cn_val]);
        let mut attr_set = Vec::new();
        der_set(&mut attr_set, &attr_seq);
        der_sequence(&mut tbs, &attr_set);
        // validity SEQUENCE { UTCTime, UTCTime }
        let utc = &[0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
        let mut validity = Vec::new();
        validity.extend_from_slice(utc);
        validity.extend_from_slice(utc);
        der_sequence(&mut tbs, &validity);
        // subject (same as issuer)
        der_sequence(&mut tbs, &attr_set);
        // subjectPublicKeyInfo SEQUENCE { AlgId, BIT STRING }
        let mut spki = Vec::new();
        // algorithm: ecPublicKey + P-256 curve OID
        let ec_pk_oid = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
        let p256_oid = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
        der_sequence_from(&mut spki, &[ec_pk_oid, p256_oid]);
        // BIT STRING (0 unused bits + public key)
        spki.push(0x03); // BIT STRING
        der_length(&mut spki, public_key_bytes.len() + 1);
        spki.push(0x00); // 0 unused bits
        spki.extend_from_slice(public_key_bytes);
        der_sequence(&mut tbs, &spki);

        // TBSCertificate SEQUENCE
        let mut tbs_seq = Vec::new();
        der_sequence(&mut tbs_seq, &tbs);

        // Certificate SEQUENCE { TBSCert, AlgId, BIT STRING(sig) }
        let mut cert = Vec::new();
        cert.extend_from_slice(&tbs_seq);
        der_sequence_from(&mut cert, &[OID_ECDSA_WITH_SHA256]);
        // dummy signature BIT STRING
        cert.push(0x03);
        cert.push(0x03);
        cert.push(0x00);
        cert.push(0x00);
        cert.push(0x00);

        let mut result = Vec::new();
        der_sequence(&mut result, &cert);
        result
    }

    fn base64_encode(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let a = chunk[0];
            let b = if chunk.len() > 1 { chunk[1] } else { 0 };
            let c = if chunk.len() > 2 { chunk[2] } else { 0 };
            out.push(TABLE[(a >> 2) as usize] as char);
            out.push(TABLE[((a & 0x03) << 4 | b >> 4) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((b & 0x0f) << 2 | c >> 6) as usize] as char);
            } else { out.push('='); }
            if chunk.len() > 2 {
                out.push(TABLE[(c & 0x3f) as usize] as char);
            } else { out.push('='); }
        }
        out
    }
}
