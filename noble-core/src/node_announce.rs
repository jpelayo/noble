// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Self-identification broadcast for PoR reputation.
//!
//! [`NodeAnnounce`] is a signed record that nodes publish via GossipSub to
//! declare their identity metadata (organization type, role, contact info).
//! The signature cryptographically binds the NOBLE identity key to the record.

use noble_codec::to_canonical_cbor;
use noble_crypto::{sha256, CryptoError, NoblePublicKey, NobleSigner, SignatureEnvelope};
use serde::{Deserialize, Serialize};

use crate::constants::{
    MAX_ATTESTATION_DATA_SIZE, MAX_NODE_NAME_LEN, MAX_ORG_NAME_LEN, MAX_SOFTWARE_VERSION_LEN,
    NODE_ANNOUNCE_MAX_AGE_SECS, NODE_ANNOUNCE_VERSION, PKI_BIND_DOMAIN_TAG,
};
use crate::encrypted_locator::ExternalAttestation;

/// Organization taxonomy — makes funding model visible.
///
/// Private and publicly-funded entities are explicitly distinguished
/// so that "state hands can be pinpointed" in the reputation system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgType {
    // ── Individual ──
    Individual,

    // ── Fully privately funded ──
    PrivateNonProfit,
    PrivateCorporation,
    PrivateStartup,
    PrivateAcademic,
    PrivateInstitution,

    // ── Public administration ──
    PublicNational,
    PublicRegional,

    // ── Publicly funded ──
    PublicSupranational,
    PublicCorporation,
    PublicAcademic,
    PublicInstitution,
}

impl std::str::FromStr for OrgType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Individual" => Ok(Self::Individual),
            "PrivateNonProfit" => Ok(Self::PrivateNonProfit),
            "PrivateCorporation" => Ok(Self::PrivateCorporation),
            "PrivateStartup" => Ok(Self::PrivateStartup),
            "PrivateAcademic" => Ok(Self::PrivateAcademic),
            "PrivateInstitution" => Ok(Self::PrivateInstitution),
            "PublicNational" => Ok(Self::PublicNational),
            "PublicRegional" => Ok(Self::PublicRegional),
            "PublicSupranational" => Ok(Self::PublicSupranational),
            "PublicCorporation" => Ok(Self::PublicCorporation),
            "PublicAcademic" => Ok(Self::PublicAcademic),
            "PublicInstitution" => Ok(Self::PublicInstitution),
            other => Err(format!("unknown OrgType: {other}")),
        }
    }
}

impl std::str::FromStr for NodeRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FullNode" => Ok(Self::FullNode),
            "Validator" => Ok(Self::Validator),
            "ArchiveNode" => Ok(Self::ArchiveNode),
            "LightClient" => Ok(Self::LightClient),
            "Gateway" => Ok(Self::Gateway),
            other => Err(format!("unknown NodeRole: {other}")),
        }
    }
}

impl OrgType {
    /// Returns the funding category for transparency.
    pub fn governance_class(&self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::PrivateNonProfit
            | Self::PrivateCorporation
            | Self::PrivateStartup
            | Self::PrivateAcademic
            | Self::PrivateInstitution => "private",
            Self::PublicNational
            | Self::PublicRegional
            | Self::PublicSupranational
            | Self::PublicCorporation
            | Self::PublicAcademic
            | Self::PublicInstitution => "public",
        }
    }

    /// All OrgType variants, useful for exhaustive iteration.
    pub fn all() -> &'static [OrgType] {
        &[
            Self::Individual,
            Self::PrivateNonProfit,
            Self::PrivateCorporation,
            Self::PrivateStartup,
            Self::PrivateAcademic,
            Self::PrivateInstitution,
            Self::PublicNational,
            Self::PublicRegional,
            Self::PublicSupranational,
            Self::PublicCorporation,
            Self::PublicAcademic,
            Self::PublicInstitution,
        ]
    }
}

/// Node's operational role in the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    FullNode,
    Validator,
    ArchiveNode,
    LightClient,
    Gateway,
}

impl NodeRole {
    /// All NodeRole variants, useful for exhaustive iteration.
    pub fn all() -> &'static [NodeRole] {
        &[
            Self::FullNode,
            Self::Validator,
            Self::ArchiveNode,
            Self::LightClient,
            Self::Gateway,
        ]
    }
}

/// Signed self-identification record broadcast via GossipSub.
///
/// Contains operator-declared metadata (not verified on-chain) plus a
/// cryptographic signature binding the NOBLE identity key to this record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeAnnounce {
    pub version: u16,
    pub identity_key: NoblePublicKey,
    pub node_name: String,
    pub org_type: OrgType,
    pub org_name: Option<String>,
    pub node_role: NodeRole,
    pub contact_email: Option<String>,
    pub website: Option<String>,
    pub host_address: Option<String>,
    /// ISO 3166-1 alpha-3 country code (e.g. "USA", "ESP", "DEU").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    pub software_version: String,
    /// Operator declares intent to produce blocks.
    #[serde(default)]
    pub wants_to_validate: bool,
    /// Operator declares intent to cast consensus votes.
    #[serde(default)]
    pub wants_to_vote: bool,
    /// Committed chain tip height (gossip-level peer discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_tip_height: Option<u64>,
    /// Committed chain tip hash (gossip-level peer discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_tip_hash: Option<[u8; 32]>,
    /// Height of the block this node is currently proposing (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_height: Option<u64>,
    /// Hash of the block this node is currently proposing (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_hash: Option<[u8; 32]>,
    pub timestamp: u64,
    pub signature: SignatureEnvelope,
    /// Optional PKI identity attestation — an external signature (PKCS#7/CMS)
    /// binding this NOBLE identity key to an X.509 certificate.
    ///
    /// **Not included in `AnnounceSigningPayload`** — the PKI signature and
    /// the NOBLE signature are independent proofs over different domains.
    /// The PKI signature covers a stable binding message:
    /// `sha256(PKI_BIND_DOMAIN_TAG || identity_key_bytes)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_attestation: Option<ExternalAttestation>,
}

/// Internal payload used to compute the signing message.
/// All fields of [`NodeAnnounce`] except `signature`.
#[derive(Serialize)]
struct AnnounceSigningPayload<'a> {
    version: u16,
    identity_key: &'a NoblePublicKey,
    node_name: &'a str,
    org_type: &'a OrgType,
    org_name: &'a Option<String>,
    node_role: &'a NodeRole,
    contact_email: &'a Option<String>,
    website: &'a Option<String>,
    host_address: &'a Option<String>,
    country_code: &'a Option<String>,
    software_version: &'a str,
    wants_to_validate: bool,
    wants_to_vote: bool,
    chain_tip_height: &'a Option<u64>,
    chain_tip_hash: &'a Option<[u8; 32]>,
    proposed_height: &'a Option<u64>,
    proposed_hash: &'a Option<[u8; 32]>,
    timestamp: u64,
}

/// Compute the PKI binding message for a given identity key (free function).
///
/// `sha256(PKI_BIND_DOMAIN_TAG || identity_key_wire_bytes)`
pub fn compute_pki_binding_message_for_key(identity_key: &NoblePublicKey) -> [u8; 32] {
    let key_bytes = identity_key.to_wire_bytes();
    let mut preimage = Vec::with_capacity(PKI_BIND_DOMAIN_TAG.len() + key_bytes.len());
    preimage.extend_from_slice(PKI_BIND_DOMAIN_TAG);
    preimage.extend_from_slice(&key_bytes);
    *sha256(&preimage).as_bytes()
}

impl NodeAnnounce {
    /// Compute the 32-byte PKI binding message for this node's identity key.
    ///
    /// This is the message that the external PKI certificate signs:
    /// `sha256(PKI_BIND_DOMAIN_TAG || identity_key_wire_bytes)`.
    ///
    /// The binding is permanent and independent of any announce refresh.
    pub fn compute_pki_binding_message(&self) -> [u8; 32] {
        compute_pki_binding_message_for_key(&self.identity_key)
    }

    /// Compute the 32-byte signing message: `sha256(canonical_cbor(payload))`.
    pub fn compute_signing_message(&self) -> Result<[u8; 32], noble_codec::CodecError> {
        let payload = AnnounceSigningPayload {
            version: self.version,
            identity_key: &self.identity_key,
            node_name: &self.node_name,
            org_type: &self.org_type,
            org_name: &self.org_name,
            node_role: &self.node_role,
            contact_email: &self.contact_email,
            website: &self.website,
            host_address: &self.host_address,
            country_code: &self.country_code,
            software_version: &self.software_version,
            wants_to_validate: self.wants_to_validate,
            wants_to_vote: self.wants_to_vote,
            chain_tip_height: &self.chain_tip_height,
            chain_tip_hash: &self.chain_tip_hash,
            proposed_height: &self.proposed_height,
            proposed_hash: &self.proposed_hash,
            timestamp: self.timestamp,
        };
        let cbor = to_canonical_cbor(&payload)?;
        Ok(*sha256(&cbor).as_bytes())
    }

    /// Verify the embedded signature against the signing payload.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let msg = self
            .compute_signing_message()
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        self.signature.verify_standalone(&msg)
    }

    /// Create a signed NodeAnnounce. The signer must correspond to `identity_key`.
    ///
    /// `identity_attestation` is an optional pre-existing PKI attestation that
    /// binds this NOBLE key to an X.509 certificate. It is stored on the
    /// announce but **not** included in the NOBLE signing payload.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity_key: NoblePublicKey,
        node_name: String,
        org_type: OrgType,
        org_name: Option<String>,
        node_role: NodeRole,
        contact_email: Option<String>,
        website: Option<String>,
        host_address: Option<String>,
        country_code: Option<String>,
        wants_to_validate: bool,
        wants_to_vote: bool,
        timestamp: u64,
        signer: &impl NobleSigner,
    ) -> Result<Self, CryptoError> {
        Self::sign_with_attestation(
            identity_key,
            node_name,
            org_type,
            org_name,
            node_role,
            contact_email,
            website,
            host_address,
            country_code,
            wants_to_validate,
            wants_to_vote,
            None,
            None,
            None,
            None,
            timestamp,
            signer,
            None,
        )
    }

    /// Create a signed NodeAnnounce with an optional PKI identity attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_attestation(
        identity_key: NoblePublicKey,
        node_name: String,
        org_type: OrgType,
        org_name: Option<String>,
        node_role: NodeRole,
        contact_email: Option<String>,
        website: Option<String>,
        host_address: Option<String>,
        country_code: Option<String>,
        wants_to_validate: bool,
        wants_to_vote: bool,
        chain_tip_height: Option<u64>,
        chain_tip_hash: Option<[u8; 32]>,
        proposed_height: Option<u64>,
        proposed_hash: Option<[u8; 32]>,
        timestamp: u64,
        signer: &impl NobleSigner,
        identity_attestation: Option<ExternalAttestation>,
    ) -> Result<Self, CryptoError> {
        use crate::constants::SOFTWARE_VERSION;
        // Build a temporary announce with a dummy signature to compute the message.
        let mut announce = Self {
            version: NODE_ANNOUNCE_VERSION,
            identity_key,
            node_name,
            org_type,
            org_name,
            node_role,
            contact_email,
            website,
            host_address,
            country_code,
            software_version: SOFTWARE_VERSION.to_string(),
            wants_to_validate,
            wants_to_vote,
            chain_tip_height,
            chain_tip_hash,
            proposed_height,
            proposed_hash,
            timestamp,
            signature: SignatureEnvelope {
                scheme_id: 0,
                public_key: vec![],
                signature: vec![],
            },
            identity_attestation,
        };

        let msg = announce
            .compute_signing_message()
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        announce.signature = signer.sign(&msg)?;
        Ok(announce)
    }

    /// Validate field lengths and timestamp freshness.
    /// Returns `Ok(())` if all structural checks pass.
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.node_name.len() > MAX_NODE_NAME_LEN {
            return Err(format!("node_name exceeds {} bytes", MAX_NODE_NAME_LEN));
        }
        if let Some(ref name) = self.org_name {
            if name.len() > MAX_ORG_NAME_LEN {
                return Err(format!("org_name exceeds {} bytes", MAX_ORG_NAME_LEN));
            }
        }
        if self.software_version.len() > MAX_SOFTWARE_VERSION_LEN {
            return Err(format!(
                "software_version exceeds {} bytes",
                MAX_SOFTWARE_VERSION_LEN
            ));
        }
        if !self
            .software_version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(
                "software_version contains invalid characters (allowed: [a-zA-Z0-9.\\-])"
                    .to_string(),
            );
        }
        if let Some(ref cc) = self.country_code {
            if cc.len() != 3 || !cc.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(
                    "country_code must be exactly 3 uppercase ASCII letters (ISO 3166-1 alpha-3)"
                        .to_string(),
                );
            }
        }
        if let Some(ref att) = self.identity_attestation {
            if att.signature_data.len() > MAX_ATTESTATION_DATA_SIZE {
                return Err(format!(
                    "identity_attestation signature_data exceeds {} bytes",
                    MAX_ATTESTATION_DATA_SIZE
                ));
            }
            if att.scope != "identity" {
                return Err(format!(
                    "identity_attestation scope must be \"identity\", got \"{}\"",
                    att.scope
                ));
            }
        }
        if self.timestamp > now {
            return Err("announce timestamp is in the future".to_string());
        }
        if now - self.timestamp > NODE_ANNOUNCE_MAX_AGE_SECS {
            return Err("announce is stale".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;
    use noble_crypto::NoblePrivateKey;

    fn make_ed25519_keypair() -> (NoblePrivateKey, NoblePublicKey) {
        let sk_bytes = [42u8; 32];
        let sk = NoblePrivateKey::Ed25519(sk_bytes.to_vec());
        let pk = sk.public_key();
        (sk, pk)
    }

    fn make_announce(sk: &NoblePrivateKey, pk: &NoblePublicKey, timestamp: u64) -> NodeAnnounce {
        NodeAnnounce::sign(
            pk.clone(),
            "test-node".to_string(),
            OrgType::Individual,
            Some("Test Org".to_string()),
            NodeRole::FullNode,
            Some("test@example.com".to_string()),
            Some("https://example.com".to_string()),
            Some("/ip4/1.2.3.4/tcp/8780".to_string()),
            None,
            false,
            false,
            timestamp,
            sk,
        )
        .unwrap()
    }

    #[test]
    fn org_type_governance_class() {
        assert_eq!(OrgType::Individual.governance_class(), "individual");
        assert_eq!(OrgType::PrivateNonProfit.governance_class(), "private");
        assert_eq!(OrgType::PrivateCorporation.governance_class(), "private");
        assert_eq!(OrgType::PrivateStartup.governance_class(), "private");
        assert_eq!(OrgType::PrivateAcademic.governance_class(), "private");
        assert_eq!(OrgType::PrivateInstitution.governance_class(), "private");
        assert_eq!(OrgType::PublicNational.governance_class(), "public");
        assert_eq!(OrgType::PublicRegional.governance_class(), "public");
        assert_eq!(OrgType::PublicSupranational.governance_class(), "public");
        assert_eq!(OrgType::PublicCorporation.governance_class(), "public");
        assert_eq!(OrgType::PublicAcademic.governance_class(), "public");
        assert_eq!(OrgType::PublicInstitution.governance_class(), "public");
    }

    #[test]
    fn node_announce_cbor_roundtrip() {
        let (sk, pk) = make_ed25519_keypair();
        let announce = make_announce(&sk, &pk, 1_700_000_000);
        let bytes = announce.to_cbor().unwrap();
        let decoded = NodeAnnounce::from_cbor(&bytes).unwrap();
        assert_eq!(announce, decoded);
    }

    #[test]
    fn signing_message_deterministic() {
        let (sk, pk) = make_ed25519_keypair();
        let announce = make_announce(&sk, &pk, 1_700_000_000);
        let msg1 = announce.compute_signing_message().unwrap();
        let msg2 = announce.compute_signing_message().unwrap();
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn verify_valid_signature() {
        let (sk, pk) = make_ed25519_keypair();
        let announce = make_announce(&sk, &pk, 1_700_000_000);
        assert!(announce.verify_signature().is_ok());
    }

    #[test]
    fn verify_tampered_signature() {
        let (sk, pk) = make_ed25519_keypair();
        let mut announce = make_announce(&sk, &pk, 1_700_000_000);
        announce.node_name = "tampered-name".to_string();
        assert!(announce.verify_signature().is_err());
    }

    #[test]
    fn verify_wrong_key() {
        let (sk, pk) = make_ed25519_keypair();
        let mut announce = make_announce(&sk, &pk, 1_700_000_000);
        // Replace identity_key with a different key
        let other_sk = NoblePrivateKey::Ed25519([99u8; 32].to_vec());
        announce.identity_key = other_sk.public_key();
        // Signature was signed by the original key, so verify should fail
        assert!(announce.verify_signature().is_err());
    }

    #[test]
    fn node_name_length_check() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let mut announce = make_announce(&sk, &pk, now);
        announce.node_name = "x".repeat(MAX_NODE_NAME_LEN + 1);
        assert!(announce.validate(now).is_err());

        announce.node_name = "x".repeat(MAX_NODE_NAME_LEN);
        assert!(announce.validate(now).is_ok());
    }

    #[test]
    fn org_name_length_check() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let mut announce = make_announce(&sk, &pk, now);
        announce.org_name = Some("x".repeat(MAX_ORG_NAME_LEN + 1));
        assert!(announce.validate(now).is_err());

        announce.org_name = Some("x".repeat(MAX_ORG_NAME_LEN));
        assert!(announce.validate(now).is_ok());
    }

    #[test]
    fn timestamp_freshness() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_010_000u64;
        // Stale: more than NODE_ANNOUNCE_MAX_AGE_SECS ago
        let announce = make_announce(&sk, &pk, now - NODE_ANNOUNCE_MAX_AGE_SECS - 1);
        assert!(announce.validate(now).is_err());

        // Fresh: within window
        let announce = make_announce(&sk, &pk, now - 100);
        assert!(announce.validate(now).is_ok());

        // Future: timestamp ahead of now
        let announce = make_announce(&sk, &pk, now + 10);
        assert!(announce.validate(now).is_err());
    }

    #[test]
    fn all_org_types_roundtrip() {
        for org_type in OrgType::all() {
            let bytes = org_type.to_cbor().unwrap();
            let decoded = OrgType::from_cbor(&bytes).unwrap();
            assert_eq!(*org_type, decoded);
        }
    }

    #[test]
    fn all_node_roles_roundtrip() {
        for role in NodeRole::all() {
            let bytes = role.to_cbor().unwrap();
            let decoded = NodeRole::from_cbor(&bytes).unwrap();
            assert_eq!(*role, decoded);
        }
    }

    #[test]
    fn participation_flags_in_cbor_roundtrip() {
        let (sk, pk) = make_ed25519_keypair();
        let announce = NodeAnnounce::sign(
            pk.clone(),
            "validator-node".to_string(),
            OrgType::PrivateCorporation,
            None,
            NodeRole::Validator,
            None,
            None,
            None,
            None,
            true,
            true,
            1_700_000_000,
            &sk,
        )
        .unwrap();
        assert!(announce.wants_to_validate);
        assert!(announce.wants_to_vote);

        let bytes = announce.to_cbor().unwrap();
        let decoded = NodeAnnounce::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.wants_to_validate, true);
        assert_eq!(decoded.wants_to_vote, true);
    }

    #[test]
    fn participation_flags_included_in_signing_message() {
        let (sk, pk) = make_ed25519_keypair();
        let a1 = NodeAnnounce::sign(
            pk.clone(),
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            1_700_000_000,
            &sk,
        )
        .unwrap();
        let a2 = NodeAnnounce::sign(
            pk.clone(),
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            true,
            true,
            1_700_000_000,
            &sk,
        )
        .unwrap();
        // Different participation flags must produce different signing messages.
        let msg1 = a1.compute_signing_message().unwrap();
        let msg2 = a2.compute_signing_message().unwrap();
        assert_ne!(msg1, msg2);
    }

    #[test]
    fn all_participation_combinations_valid() {
        let (sk, pk) = make_ed25519_keypair();
        for (v, vote) in [(false, false), (true, false), (false, true), (true, true)] {
            let a = NodeAnnounce::sign(
                pk.clone(),
                "test".to_string(),
                OrgType::Individual,
                None,
                NodeRole::FullNode,
                None,
                None,
                None,
                None,
                v,
                vote,
                1_700_000_000,
                &sk,
            )
            .unwrap();
            assert!(a.verify_signature().is_ok());
            assert_eq!(a.wants_to_validate, v);
            assert_eq!(a.wants_to_vote, vote);
        }
    }

    #[test]
    fn governance_class_covers_all_variants() {
        // Ensure all() returns 12 variants and all have a governance class.
        let all = OrgType::all();
        assert_eq!(all.len(), 12);
        let valid_classes = ["individual", "private", "public"];
        for org in all {
            let class = org.governance_class();
            assert!(
                valid_classes.contains(&class),
                "unexpected governance class: {class}"
            );
        }
    }

    // ── PKI Identity Attestation Tests ──

    fn make_test_attestation(scope: &str, data_size: usize) -> ExternalAttestation {
        use crate::encrypted_locator::ExternalAttestation;
        ExternalAttestation {
            scheme: "pkcs7".to_string(),
            scope: scope.to_string(),
            signer_fingerprint: [0xAB; 32],
            signature_data: vec![0xCC; data_size],
        }
    }

    #[test]
    fn pki_binding_message_deterministic() {
        let (_, pk) = make_ed25519_keypair();
        let msg1 = compute_pki_binding_message_for_key(&pk);
        let msg2 = compute_pki_binding_message_for_key(&pk);
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn pki_binding_message_differs_per_key() {
        let sk1 = NoblePrivateKey::Ed25519([42u8; 32].to_vec());
        let sk2 = NoblePrivateKey::Ed25519([99u8; 32].to_vec());
        let msg1 = compute_pki_binding_message_for_key(&sk1.public_key());
        let msg2 = compute_pki_binding_message_for_key(&sk2.public_key());
        assert_ne!(msg1, msg2);
    }

    #[test]
    fn announce_with_attestation_roundtrip() {
        let (sk, pk) = make_ed25519_keypair();
        let att = make_test_attestation("identity", 256);
        let announce = NodeAnnounce::sign_with_attestation(
            pk.clone(),
            "test-node".to_string(),
            OrgType::PrivateCorporation,
            Some("Acme Corp".to_string()),
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            1_700_000_000,
            &sk,
            Some(att.clone()),
        )
        .unwrap();
        assert!(announce.identity_attestation.is_some());

        // CBOR roundtrip preserves attestation
        let bytes = announce.to_cbor().unwrap();
        let decoded = NodeAnnounce::from_cbor(&bytes).unwrap();
        assert_eq!(
            decoded.identity_attestation.as_ref().unwrap().scheme,
            "pkcs7"
        );
        assert_eq!(
            decoded.identity_attestation.as_ref().unwrap().scope,
            "identity"
        );
        assert_eq!(
            decoded
                .identity_attestation
                .as_ref()
                .unwrap()
                .signature_data
                .len(),
            256
        );
    }

    #[test]
    fn attestation_not_in_signing_payload() {
        let (sk, pk) = make_ed25519_keypair();
        let att = make_test_attestation("identity", 128);
        // Build identical announces — one with attestation, one without
        let with = NodeAnnounce::sign_with_attestation(
            pk.clone(),
            "test-node".to_string(),
            OrgType::Individual,
            Some("Test Org".to_string()),
            NodeRole::FullNode,
            Some("test@example.com".to_string()),
            Some("https://example.com".to_string()),
            Some("/ip4/1.2.3.4/tcp/8780".to_string()),
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            1_700_000_000,
            &sk,
            Some(att),
        )
        .unwrap();
        let without = make_announce(&sk, &pk, 1_700_000_000);

        // Signing message is the same with or without attestation
        let msg_with = with.compute_signing_message().unwrap();
        let msg_without = without.compute_signing_message().unwrap();
        assert_eq!(msg_with, msg_without);
    }

    #[test]
    fn attestation_wrong_scope_rejected() {
        let (sk, pk) = make_ed25519_keypair();
        let att = make_test_attestation("hash", 128); // wrong scope
        let announce = NodeAnnounce::sign_with_attestation(
            pk.clone(),
            "test-node".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            1_700_000_000,
            &sk,
            Some(att),
        )
        .unwrap();
        let result = announce.validate(1_700_000_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("scope must be \"identity\""));
    }

    #[test]
    fn attestation_too_large_rejected() {
        let (sk, pk) = make_ed25519_keypair();
        let att = make_test_attestation("identity", MAX_ATTESTATION_DATA_SIZE + 1);
        let announce = NodeAnnounce::sign_with_attestation(
            pk.clone(),
            "test-node".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            1_700_000_000,
            &sk,
            Some(att),
        )
        .unwrap();
        let result = announce.validate(1_700_000_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds"));
    }

    // ── Country Code Tests ──

    #[test]
    fn country_code_valid_accepted() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let announce = NodeAnnounce::sign(
            pk.clone(),
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            Some("USA".to_string()),
            false,
            false,
            now,
            &sk,
        )
        .unwrap();
        assert!(announce.validate(now).is_ok());
        assert_eq!(announce.country_code, Some("USA".to_string()));
    }

    #[test]
    fn country_code_none_accepted() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let announce = make_announce(&sk, &pk, now);
        assert!(announce.validate(now).is_ok());
        assert_eq!(announce.country_code, None);
    }

    #[test]
    fn country_code_invalid_too_short() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let mut announce = make_announce(&sk, &pk, now);
        announce.country_code = Some("US".to_string());
        assert!(announce.validate(now).unwrap_err().contains("country_code"));
    }

    #[test]
    fn country_code_invalid_too_long() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let mut announce = make_announce(&sk, &pk, now);
        announce.country_code = Some("USAA".to_string());
        assert!(announce.validate(now).unwrap_err().contains("country_code"));
    }

    #[test]
    fn country_code_invalid_non_alpha() {
        let (sk, pk) = make_ed25519_keypair();
        let now = 1_700_000_000u64;
        let mut announce = make_announce(&sk, &pk, now);
        announce.country_code = Some("12A".to_string());
        assert!(announce.validate(now).unwrap_err().contains("country_code"));
    }

    #[test]
    fn country_code_in_signing_message() {
        let (sk, pk) = make_ed25519_keypair();
        let a1 = NodeAnnounce::sign(
            pk.clone(),
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            Some("USA".to_string()),
            false,
            false,
            1_700_000_000,
            &sk,
        )
        .unwrap();
        let a2 = NodeAnnounce::sign(
            pk.clone(),
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            Some("ESP".to_string()),
            false,
            false,
            1_700_000_000,
            &sk,
        )
        .unwrap();
        let msg1 = a1.compute_signing_message().unwrap();
        let msg2 = a2.compute_signing_message().unwrap();
        assert_ne!(msg1, msg2);
    }

    // ── FromStr Tests ──

    #[test]
    fn org_type_from_str_roundtrip() {
        for org in OrgType::all() {
            let name = format!("{:?}", org);
            let parsed: OrgType = name.parse().unwrap();
            assert_eq!(*org, parsed);
        }
    }

    #[test]
    fn org_type_from_str_unknown() {
        let result: Result<OrgType, _> = "Bogus".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown OrgType"));
    }

    #[test]
    fn node_role_from_str_roundtrip() {
        for role in NodeRole::all() {
            let name = format!("{:?}", role);
            let parsed: NodeRole = name.parse().unwrap();
            assert_eq!(*role, parsed);
        }
    }

    #[test]
    fn node_role_from_str_unknown() {
        let result: Result<NodeRole, _> = "Bogus".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown NodeRole"));
    }
}
