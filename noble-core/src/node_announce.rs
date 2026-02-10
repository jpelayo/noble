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
    MAX_NODE_NAME_LEN, MAX_ORG_NAME_LEN, NODE_ANNOUNCE_MAX_AGE_SECS, NODE_ANNOUNCE_VERSION,
};

/// Organization taxonomy — makes governance model visible.
///
/// Government, for-profit, and non-profit entities are explicitly
/// distinguished so that "state hands can be pinpointed" in the
/// reputation system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgType {
    // ── Individuals ──
    Individual,
    IndependentResearcher,

    // ── Non-Profit / Academic ──
    University,
    ResearchLab,
    NGO,
    Foundation,
    OpenSourceProject,
    Cooperative,
    CommunityGroup,
    ReligiousOrganization,

    // ── For-Profit ──
    Enterprise,
    Startup,
    InfrastructureProvider,
    FinancialInstitution,

    // ── Government & State (pinpointed) ──
    GovernmentFederal,
    GovernmentRegional,
    GovernmentMunicipal,
    MilitaryOrDefense,
    CentralBank,

    // ── Institutional / Mixed ──
    Hospital,
    Museum,
    MediaOutlet,
}

impl OrgType {
    /// Returns the governance category for transparency.
    pub fn governance_class(&self) -> &'static str {
        match self {
            Self::Individual | Self::IndependentResearcher => "individual",
            Self::University
            | Self::ResearchLab
            | Self::NGO
            | Self::Foundation
            | Self::OpenSourceProject
            | Self::Cooperative
            | Self::CommunityGroup
            | Self::ReligiousOrganization => "non-profit",
            Self::Enterprise
            | Self::Startup
            | Self::InfrastructureProvider
            | Self::FinancialInstitution => "for-profit",
            Self::GovernmentFederal
            | Self::GovernmentRegional
            | Self::GovernmentMunicipal
            | Self::MilitaryOrDefense
            | Self::CentralBank => "government",
            Self::Hospital | Self::Museum | Self::MediaOutlet => "institution",
        }
    }

    /// All OrgType variants, useful for exhaustive iteration.
    pub fn all() -> &'static [OrgType] {
        &[
            Self::Individual,
            Self::IndependentResearcher,
            Self::University,
            Self::ResearchLab,
            Self::NGO,
            Self::Foundation,
            Self::OpenSourceProject,
            Self::Cooperative,
            Self::CommunityGroup,
            Self::ReligiousOrganization,
            Self::Enterprise,
            Self::Startup,
            Self::InfrastructureProvider,
            Self::FinancialInstitution,
            Self::GovernmentFederal,
            Self::GovernmentRegional,
            Self::GovernmentMunicipal,
            Self::MilitaryOrDefense,
            Self::CentralBank,
            Self::Hospital,
            Self::Museum,
            Self::MediaOutlet,
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
    pub timestamp: u64,
    pub signature: SignatureEnvelope,
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
    timestamp: u64,
}

impl NodeAnnounce {
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
        timestamp: u64,
        signer: &impl NobleSigner,
    ) -> Result<Self, CryptoError> {
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
            timestamp,
            signature: SignatureEnvelope {
                scheme_id: 0,
                public_key: vec![],
                signature: vec![],
            },
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
            Some("/ip4/1.2.3.4/tcp/9333".to_string()),
            timestamp,
            sk,
        )
        .unwrap()
    }

    #[test]
    fn org_type_governance_class() {
        assert_eq!(OrgType::Individual.governance_class(), "individual");
        assert_eq!(
            OrgType::IndependentResearcher.governance_class(),
            "individual"
        );
        assert_eq!(OrgType::University.governance_class(), "non-profit");
        assert_eq!(OrgType::ResearchLab.governance_class(), "non-profit");
        assert_eq!(OrgType::NGO.governance_class(), "non-profit");
        assert_eq!(OrgType::Foundation.governance_class(), "non-profit");
        assert_eq!(OrgType::OpenSourceProject.governance_class(), "non-profit");
        assert_eq!(OrgType::Cooperative.governance_class(), "non-profit");
        assert_eq!(OrgType::CommunityGroup.governance_class(), "non-profit");
        assert_eq!(
            OrgType::ReligiousOrganization.governance_class(),
            "non-profit"
        );
        assert_eq!(OrgType::Enterprise.governance_class(), "for-profit");
        assert_eq!(OrgType::Startup.governance_class(), "for-profit");
        assert_eq!(
            OrgType::InfrastructureProvider.governance_class(),
            "for-profit"
        );
        assert_eq!(
            OrgType::FinancialInstitution.governance_class(),
            "for-profit"
        );
        assert_eq!(OrgType::GovernmentFederal.governance_class(), "government");
        assert_eq!(OrgType::GovernmentRegional.governance_class(), "government");
        assert_eq!(
            OrgType::GovernmentMunicipal.governance_class(),
            "government"
        );
        assert_eq!(OrgType::MilitaryOrDefense.governance_class(), "government");
        assert_eq!(OrgType::CentralBank.governance_class(), "government");
        assert_eq!(OrgType::Hospital.governance_class(), "institution");
        assert_eq!(OrgType::Museum.governance_class(), "institution");
        assert_eq!(OrgType::MediaOutlet.governance_class(), "institution");
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
    fn governance_class_covers_all_variants() {
        // Ensure all() returns 22 variants and all have a governance class.
        let all = OrgType::all();
        assert_eq!(all.len(), 22);
        let valid_classes = [
            "individual",
            "non-profit",
            "for-profit",
            "government",
            "institution",
        ];
        for org in all {
            let class = org.governance_class();
            assert!(
                valid_classes.contains(&class),
                "unexpected governance class: {class}"
            );
        }
    }
}
