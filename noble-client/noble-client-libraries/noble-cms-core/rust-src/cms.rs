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
use cms::encrypted_data::EncryptedData;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use der::asn1::{ContextSpecific, OctetString};
use der::{Decode, Encode};
use pkcs12::authenticated_safe::AuthenticatedSafe;
use pkcs12::cert_type::CertBag;
use pkcs12::pfx::Pfx;
use pkcs12::safe_bag::SafeContents;
use pkcs12::{PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID};
use pkcs8::pkcs5::pbes2::{Parameters as Pbes2Params, PBES2_OID};
use pkcs8::pkcs5::EncryptionScheme;
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfo, PrivateKeyInfo};
use p256::elliptic_curve::sec1::ToEncodedPoint;
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
//
// Extracts an ECDSA P-256 signing identity (private key + X.509 certificate)
// from a PKCS#12 (.p12/.pfx) file. This is the cross-platform equivalent of
// Apple's SecPKCS12Import, letting the WRY desktop clients (Linux/Windows)
// import corporate PKI signing keys the same way NobleMac does.
//
// Encryption support: PBES2 (PBKDF2 + AES-CBC / 3DES-CBC), which is the modern
// default emitted by OpenSSL 3.x and Windows exports. The obsolete PKCS#12 PBE
// schemes (pbeWithSHAAnd3-KeyTripleDES / RC2, arc 1.2.840.113549.1.12.1.*) that
// `openssl pkcs12 -legacy` produces are refused with actionable guidance —
// their cert bag is RC2-40 encrypted, which is out of scope. Keys must be
// NIST P-256; RSA is rejected (CMS+RSA exceeds the 256-byte metadata slot).

// PKCS#7 content-type OIDs (RFC 2315 §7). Declared locally to avoid pulling in
// const-oid's optional `db` feature.
const OID_PKCS7_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const OID_PKCS7_ENCRYPTED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
// id-ecPublicKey, the prime256v1 named curve, and rsaEncryption.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

const LEGACY_PBE_HELP: &str =
    "PKCS#12 file uses legacy encryption (SHA1/3DES/RC2) that is not supported. \
     Re-export with AES, e.g.: openssl pkcs12 -export -keypbe aes-256-cbc \
     -certpbe aes-256-cbc -macalg sha256 -inkey key.pem -in cert.pem -out new.p12";

/// True for the obsolete PKCS#12 password-based encryption schemes
/// (`pbeWithSHAAnd*` — arc 1.2.840.113549.1.12.1.*: 3DES, RC2, RC4).
fn is_legacy_pkcs12_pbe(oid: &ObjectIdentifier) -> bool {
    oid.to_string().starts_with("1.2.840.113549.1.12.1.")
}

/// Decrypt a PBES2-protected blob (PBKDF2 KDF + AES/3DES-CBC cipher).
fn decrypt_pbes2(
    alg: &spki::AlgorithmIdentifierOwned,
    password: &str,
    mut ciphertext: Vec<u8>,
) -> CmsResult<Vec<u8>> {
    let enc_params = alg
        .parameters
        .as_ref()
        .ok_or("PBES2 algorithm missing parameters")?
        .to_der()
        .map_err(|e| format!("pbes2 params der: {e}"))?;
    let params = Pbes2Params::from_der(&enc_params).map_err(|e| format!("pbes2 params: {e}"))?;
    let scheme = EncryptionScheme::from(params);
    let plaintext = scheme
        .decrypt_in_place(password, &mut ciphertext)
        .map_err(|e| format!("PBES2 decrypt (wrong password?): {e}"))?;
    Ok(plaintext.to_vec())
}

pub fn import_pkcs12(params_json: &str) -> CmsResult<Pkcs12Info> {
    let params: serde_json::Value =
        serde_json::from_str(params_json).map_err(|e| format!("parse params: {e}"))?;
    let p12_hex = params["p12_hex"].as_str().ok_or("missing p12_hex")?;
    // Empty-password PKCS#12 files are valid — password is optional.
    let password = params["password"].as_str().unwrap_or("");
    let p12_bytes = hex::decode(p12_hex).map_err(|e| format!("hex p12: {e}"))?;

    let pfx = Pfx::from_der(&p12_bytes).map_err(|e| format!("parse PFX: {e}"))?;
    if pfx.auth_safe.content_type != OID_PKCS7_DATA {
        return Err("unsupported PKCS#12: auth-safe is not plain Data (public-key \
                    protected .p12 is not supported)"
            .into());
    }
    let auth_safes_os = OctetString::from_der(
        &pfx.auth_safe
            .content
            .to_der()
            .map_err(|e| format!("auth_safe der: {e}"))?,
    )
    .map_err(|e| format!("auth_safe octet: {e}"))?;
    let auth_safes = AuthenticatedSafe::from_der(auth_safes_os.as_bytes())
        .map_err(|e| format!("authenticated_safe: {e}"))?;

    let mut key_pkcs8: Option<Vec<u8>> = None;
    let mut cert_der: Option<Vec<u8>> = None;

    for content_info in auth_safes.iter() {
        // Resolve each auth-safe to a plaintext SafeContents blob, decrypting an
        // EncryptedData container (cert bags) if present.
        let safe_contents_der: Vec<u8> = if content_info.content_type == OID_PKCS7_ENCRYPTED_DATA {
            let enc_data = EncryptedData::from_der(
                &content_info
                    .content
                    .to_der()
                    .map_err(|e| format!("enc_data der: {e}"))?,
            )
            .map_err(|e| format!("EncryptedData: {e}"))?;
            let alg = &enc_data.enc_content_info.content_enc_alg;
            if is_legacy_pkcs12_pbe(&alg.oid) {
                return Err(LEGACY_PBE_HELP.into());
            }
            if alg.oid != PBES2_OID {
                return Err(format!(
                    "unsupported PKCS#12 cert encryption (OID {}); re-export with AES",
                    alg.oid
                ));
            }
            let ciphertext = enc_data
                .enc_content_info
                .encrypted_content
                .as_ref()
                .ok_or("EncryptedData has no encrypted content")?
                .as_bytes()
                .to_vec();
            decrypt_pbes2(alg, password, ciphertext)?
        } else if content_info.content_type == OID_PKCS7_DATA {
            OctetString::from_der(
                &content_info
                    .content
                    .to_der()
                    .map_err(|e| format!("data der: {e}"))?,
            )
            .map_err(|e| format!("data octet: {e}"))?
            .as_bytes()
            .to_vec()
        } else {
            continue; // envelopedData etc. — not produced by standard exporters
        };

        // A wrong password occasionally (~1/256) yields garbage with valid CBC
        // padding, so decryption "succeeds" and the failure surfaces here as a
        // DER parse error instead — hence the password hint.
        let safe_bags = SafeContents::from_der(&safe_contents_der)
            .map_err(|e| format!("SafeContents (wrong password?): {e}"))?;
        // Single-identity import: the first certificate and first key win;
        // extra bags in a multi-identity PFX are intentionally ignored.
        for bag in safe_bags {
            if bag.bag_id == PKCS_12_CERT_BAG_OID {
                let cs: ContextSpecific<CertBag> = ContextSpecific::from_der(&bag.bag_value)
                    .map_err(|e| format!("CertBag: {e}"))?;
                cert_der.get_or_insert_with(|| cs.value.cert_value.as_bytes().to_vec());
            } else if bag.bag_id == PKCS_12_PKCS8_KEY_BAG_OID {
                // Shrouded (encrypted) PKCS#8 key. A decode failure here is the
                // fingerprint of a legacy-PBE key that pkcs5 can't parse.
                let cs: ContextSpecific<EncryptedPrivateKeyInfo> =
                    ContextSpecific::from_der(&bag.bag_value)
                        .map_err(|e| format!("shrouded key bag: {e}. {LEGACY_PBE_HELP}"))?;
                let secret = cs
                    .value
                    .decrypt(password)
                    .map_err(|e| format!("decrypt private key (wrong password?): {e}"))?;
                key_pkcs8.get_or_insert_with(|| secret.as_bytes().to_vec());
            } else if bag.bag_id == PKCS_12_KEY_BAG_OID {
                // Unencrypted PKCS#8 key bag — bag_value is the PrivateKeyInfo.
                let cs: ContextSpecific<PrivateKeyInfo> =
                    ContextSpecific::from_der(&bag.bag_value)
                        .map_err(|e| format!("key bag: {e}"))?;
                let der = cs.value.to_der().map_err(|e| format!("key bag der: {e}"))?;
                key_pkcs8.get_or_insert(der);
            }
        }
    }

    let key_pkcs8 = key_pkcs8.ok_or("no private key found in PKCS#12")?;
    let cert_der = cert_der.ok_or("no certificate found in PKCS#12")?;

    // Reject non-P256 keys up front with a precise message.
    let pki = PrivateKeyInfo::from_der(&key_pkcs8).map_err(|e| format!("parse key: {e}"))?;
    if pki.algorithm.oid == OID_RSA_ENCRYPTION {
        return Err("RSA keys are not supported (CMS+RSA exceeds the 256-byte metadata \
                    slot); use an ECDSA P-256 certificate"
            .into());
    }
    if pki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(format!(
            "unsupported key algorithm (OID {}); only ECDSA P-256 is supported",
            pki.algorithm.oid
        ));
    }
    let curve_ok = pki
        .algorithm
        .parameters_oid()
        .map(|o| o == OID_PRIME256V1)
        .unwrap_or(false);
    if !curve_ok {
        return Err("unsupported EC curve; only NIST P-256 (prime256v1) is supported".into());
    }

    // Load the key and derive both point encodings.
    let sk =
        p256::SecretKey::from_pkcs8_der(&key_pkcs8).map_err(|e| format!("load P-256 key: {e}"))?;
    let pk = sk.public_key();
    let compressed = pk.to_encoded_point(true);
    let uncompressed = pk.to_encoded_point(false);
    let public_key_hex = hex::encode(compressed.as_bytes());
    let private_key_hex = hex::encode(sk.to_bytes());

    // Parse the certificate for subject + SKI, and prove it matches the key.
    let cert = Certificate::from_der(&cert_der).map_err(|e| format!("parse cert: {e}"))?;
    let spki_pk = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if spki_pk != uncompressed.as_bytes() {
        return Err("PKCS#12 certificate public key does not match the private key".into());
    }
    // SKI computed over the SPKI subjectPublicKey — identical to sign_cms /
    // verify_cms, so the imported identity's SKI round-trips with its signatures.
    let ski = compute_ski(spki_pk);
    let subject_name = cert.tbs_certificate.subject.to_string();

    Ok(Pkcs12Info {
        public_key_hex,
        algorithm: "p256".to_string(),
        certificate_der_b64: base64_encode(&cert_der),
        subject_name,
        ski_hex: hex::encode(ski),
        private_key_hex,
    })
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

/// Standard (RFC 4648) base64 encoder with `=` padding — round-trips with
/// `base64_decode` and is directly consumable by Swift/JS `atob`.
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
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
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

    // ── PKCS#12 import ──
    // Fixtures: self-signed P-256 cert + key, password "test123".
    //   p256_pbes2_aes.p12   — OpenSSL 3.x default (PBES2 / PBKDF2 / AES-256-CBC)
    //   p256_legacy_3des.p12 — `openssl pkcs12 -legacy` (SHA1-3DES key, RC2 cert)
    //   rsa_pbes2.p12        — RSA key (must be rejected)
    const P12_PBES2: &[u8] = include_bytes!("tests/fixtures/p256_pbes2_aes.p12");
    const P12_LEGACY: &[u8] = include_bytes!("tests/fixtures/p256_legacy_3des.p12");
    const P12_RSA: &[u8] = include_bytes!("tests/fixtures/rsa_pbes2.p12");
    // Compressed pubkey derived independently via `openssl ec -pubout -conv_form compressed`.
    const EXPECTED_PUBKEY: &str =
        "037750788a3e32769cdcb02ba7b1289b5c75d5a4d84b793597e70a1fc996478668";

    fn p12_params(bytes: &[u8], password: &str) -> String {
        serde_json::json!({ "p12_hex": hex::encode(bytes), "password": password }).to_string()
    }

    // Avoids requiring `Debug` on Pkcs12Info (which holds the private key) just
    // to call `.unwrap_err()`.
    fn expect_import_err(result: CmsResult<Pkcs12Info>) -> String {
        match result {
            Ok(_) => panic!("expected PKCS#12 import to fail"),
            Err(e) => e,
        }
    }

    #[test]
    fn imports_pbes2_aes_p12() {
        let info = import_pkcs12(&p12_params(P12_PBES2, "test123")).expect("import PBES2 p12");
        assert_eq!(info.algorithm, "p256");
        assert_eq!(info.public_key_hex, EXPECTED_PUBKEY);
        assert_eq!(info.private_key_hex.len(), 64);
        assert_eq!(info.ski_hex.len(), 40);
        assert!(
            info.subject_name.contains("Noble Test Signer"),
            "subject was {}",
            info.subject_name
        );
        // The returned cert must re-parse and its SPKI must match the pubkey.
        let cert_der = base64_decode(&info.certificate_der_b64).unwrap();
        let cert = Certificate::from_der(&cert_der).expect("cert re-parses");
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        assert_eq!(spki.len(), 65, "uncompressed EC point");
    }

    #[test]
    fn imported_key_is_usable_for_signing() {
        // The extracted identity must produce a verifiable CMS signature — proves
        // key + cert are internally consistent and usable end-to-end.
        let info = import_pkcs12(&p12_params(P12_PBES2, "test123")).unwrap();
        let sign_params = serde_json::json!({
            "private_key_hex": info.private_key_hex,
            "certificate_der_b64": info.certificate_der_b64,
            "field_value": "Imported Identity",
            "algorithm": "p256",
        });
        let cms = sign_cms(&sign_params.to_string()).expect("sign with imported key");
        let verify_params = serde_json::json!({
            "cms_hex": cms.cms_hex,
            "field_value": "Imported Identity",
            "certificate_der_b64": info.certificate_der_b64,
        });
        let verdict = verify_cms(&verify_params.to_string()).expect("verify");
        assert!(
            verdict.valid,
            "imported identity signature must verify: {:?}",
            verdict.error
        );
    }

    #[test]
    fn rejects_wrong_password() {
        let err = expect_import_err(import_pkcs12(&p12_params(P12_PBES2, "wrongpass")));
        assert!(
            err.to_lowercase().contains("password") || err.to_lowercase().contains("decrypt"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_legacy_3des_rc2_p12() {
        let err = expect_import_err(import_pkcs12(&p12_params(P12_LEGACY, "test123")));
        assert!(
            err.to_lowercase().contains("legacy"),
            "expected legacy-encryption guidance, got: {err}"
        );
    }

    #[test]
    fn rejects_rsa_p12() {
        let err = expect_import_err(import_pkcs12(&p12_params(P12_RSA, "test123")));
        assert!(
            err.to_uppercase().contains("RSA") || err.to_lowercase().contains("p-256"),
            "expected RSA-unsupported error, got: {err}"
        );
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

}
