// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-serializable response structs for the NOBLE RPC API.

use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

use noble_core::{Block, NobleAddress, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a `Hash256` to a lowercase hex string.
pub fn hash_to_hex(h: &Hash256) -> String {
    hex::encode(h.as_bytes())
}

/// Parse a hex-encoded wire-format public key, returning a JSON-RPC error on failure.
pub fn parse_pubkey(hex_str: &str) -> Result<NoblePublicKey, ErrorObjectOwned> {
    let bytes =
        hex::decode(hex_str).map_err(|_| ApiError::InvalidAddress("invalid hex string".into()))?;
    NoblePublicKey::from_wire_bytes(&bytes)
        .map_err(|e| ApiError::InvalidAddress(e.to_string()).into())
}

/// Parse an address string into a `NobleAddress`.
///
/// Accepts:
/// - Hex-encoded wire-format NOBLE public keys (Ed25519: 0x01, secp256k1: 0x02)
/// - Bitcoin addresses: P2PKH (1...), P2WPKH (bc1q...), P2TR (bc1p...)
/// - Hex-encoded Bitcoin address wire bytes (0x80, 0x81 prefix)
pub fn parse_address(input: &str) -> Result<NobleAddress, ErrorObjectOwned> {
    let trimmed = input.trim();

    // Try Bitcoin address formats first (bc1q..., bc1p..., 1..., tb1...)
    if trimmed.starts_with("bc1")
        || trimmed.starts_with("BC1")
        || trimmed.starts_with("tb1")
        || trimmed.starts_with("TB1")
        || trimmed.starts_with('1')
        || trimmed.starts_with('m')
        || trimmed.starts_with('n')
        || trimmed.starts_with('3')
        || trimmed.starts_with('2')
    {
        use noble_crypto::bitcoin_addr::{parse_bitcoin_address, BitcoinAddressType};
        let parsed = parse_bitcoin_address(trimmed)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;
        return match parsed.address_type {
            BitcoinAddressType::P2pkh | BitcoinAddressType::P2wpkh => {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&parsed.data);
                Ok(NobleAddress::BitcoinHash160(hash))
            }
            BitcoinAddressType::P2tr => {
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&parsed.data);
                Ok(NobleAddress::BitcoinTaproot(xonly))
            }
        };
    }

    // Try hex-encoded wire bytes (covers both NOBLE keys and Bitcoin address wire format)
    let bytes = hex::decode(trimmed)
        .map_err(|_| ApiError::InvalidAddress("invalid hex string or unrecognized address format".into()))?;
    NobleAddress::from_wire_bytes(&bytes)
        .map_err(|e| ApiError::InvalidAddress(e.to_string()).into())
}

/// Parse a hex string into a `Hash256`, returning a JSON-RPC error on failure.
pub fn parse_hash(hex_str: &str) -> Result<Hash256, ErrorObjectOwned> {
    let bytes =
        hex::decode(hex_str).map_err(|_| ApiError::InvalidAddress("invalid hex string".into()))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidAddress(format!(
            "hash must be 32 bytes, got {}",
            bytes.len()
        ))
        .into());
    }
    let arr: [u8; 32] = bytes.try_into().unwrap();
    Ok(Hash256::from_bytes(arr))
}

/// Convert a `Block` to a `BlockResponse`.
pub fn block_to_response(block: &Block, block_hash: &Hash256, chain_id: u32) -> BlockResponse {
    let txs: Vec<TransactionResponse> = block
        .transactions
        .iter()
        .map(|tx| {
            let tx_id = tx
                .compute_tx_id(chain_id)
                .map(|id| hash_to_hex(&id))
                .unwrap_or_default();
            tx_to_response(tx, &tx_id)
        })
        .collect();

    BlockResponse {
        height: block.header.height,
        hash: hash_to_hex(block_hash),
        prev_hash: hash_to_hex(&block.header.prev_block_hash),
        merkle_root: hash_to_hex(&block.header.merkle_root),
        timestamp: block.header.timestamp,
        tx_count: block.header.tx_count,
        validator_id: hex::encode(block.header.validator_id.to_wire_bytes()),
        transactions: txs,
    }
}

/// Convert a `Transaction` to a `TransactionResponse`.
pub fn tx_to_response(tx: &Transaction, tx_id: &str) -> TransactionResponse {
    let has_locator = tx.encrypted_locator.is_some();
    let locator_recipients = tx
        .encrypted_locator
        .as_ref()
        .map_or(0, |l| l.recipients.len());

    TransactionResponse {
        tx_id: tx_id.to_string(),
        tx_type: tx.tx_type,
        checksum: hash_to_hex(&tx.checksum),
        timestamp: tx.timestamp,
        fee: tx.fee,
        recipient: tx
            .recipient
            .as_ref()
            .map(|r| hex::encode(r.to_wire_bytes())),
        amount: tx.amount,
        signer: hex::encode(&tx.publisher_sig.public_key),
        metadata: tx
            .metadata
            .iter()
            .map(|m| MetadataResponse {
                key: m.key.clone(),
                value: hex::encode(&m.value),
            })
            .collect(),
        has_encrypted_locator: has_locator,
        locator_recipient_count: locator_recipients,
        attestation_count: tx.external_attestations.len(),
        attestations: tx
            .external_attestations
            .iter()
            .map(|a| AttestationResponse {
                scheme: a.scheme.clone(),
                scope: a.scope.clone(),
                signer_fingerprint: hex::encode(a.signer_fingerprint),
                signature_size: a.signature_data.len(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response for `noble_getBlockCount`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockCountResponse {
    pub height: u64,
    pub block_hash: String,
}

/// Full block response for `noble_getBlock` / `noble_getLatestBlock`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub tx_count: u32,
    pub validator_id: String,
    pub transactions: Vec<TransactionResponse>,
}

/// Header-only block response for `noble_getBlockHeader` / `noble_getBlockRange`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockHeaderResponse {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub tx_count: u32,
    pub validator_id: String,
}

/// Transaction response used in blocks and standalone queries.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionResponse {
    pub tx_id: String,
    pub tx_type: u8,
    pub checksum: String,
    pub timestamp: u64,
    pub fee: u64,
    pub recipient: Option<String>,
    pub amount: Option<u64>,
    pub signer: String,
    pub metadata: Vec<MetadataResponse>,
    pub has_encrypted_locator: bool,
    pub locator_recipient_count: usize,
    pub attestation_count: usize,
    pub attestations: Vec<AttestationResponse>,
}

/// External attestation response (protocol-opaque, for display only).
#[derive(Debug, Clone, Serialize)]
pub struct AttestationResponse {
    pub scheme: String,
    pub scope: String,
    pub signer_fingerprint: String,
    pub signature_size: usize,
}

/// Metadata entry response (key + hex-encoded value).
#[derive(Debug, Clone, Serialize)]
pub struct MetadataResponse {
    pub key: String,
    pub value: String,
}

/// Response for `noble_submitTransaction`.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitTxResponse {
    pub tx_id: String,
    pub accepted: bool,
}

/// A single document registration record with block context.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationRecord {
    pub block_height: u64,
    pub tx_id: String,
    pub timestamp: u64,
    /// `doc:version` metadata value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `doc:prev_checksum` metadata value (hex), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_checksum: Option<String>,
}

/// Response for `noble_lookupChecksum`.
#[derive(Debug, Clone, Serialize)]
pub struct ChecksumLookupResponse {
    pub found: bool,
    pub records: Vec<RegistrationRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_chain: Option<Vec<VersionEntry>>,
}

/// Response for `noble_getChainStats`.
#[derive(Debug, Clone, Serialize)]
pub struct ChainStatsResponse {
    pub height: u64,
    pub total_transactions: u64,
    pub chain_id: u32,
}

/// Response for `noble_estimateFee`.
#[derive(Debug, Clone, Serialize)]
pub struct FeeEstimateResponse {
    pub min_fee: u64,
    pub recommended_fee: u64,
    pub high_priority_fee: u64,
}

/// Response for `noble_getMempoolInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct MempoolInfoResponse {
    pub count: usize,
    pub total_bytes: usize,
    pub min_fee: u64,
    pub max_fee: u64,
    pub avg_fee: u64,
}

/// Individual peer information.
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfoResponse {
    pub peer_id: String,
    pub direction: String,
    pub addr: Option<String>,
    pub node_name: Option<String>,
    pub country_code: Option<String>,
    pub connected_at: u64,
    pub ban_score: u32,
    pub last_ban_reason: Option<BanReasonResponse>,
    /// Connection status: "connected" or "disconnected".
    pub status: String,
    /// Peer's chain tip height (from last status exchange).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_tip_height: Option<u64>,
    /// Peer's chain tip hash (from last status exchange).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_tip_hash: Option<String>,
}

/// Response for `noble_getNetworkInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInfoResponse {
    pub peer_count: usize,
    pub inbound: usize,
    pub outbound: usize,
}

/// Response for `noble_getSyncStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatusResponse {
    pub synced: bool,
    pub current_height: u64,
    pub highest_known: u64,
    pub progress: f64,
    pub state: String,
}

/// A persistent peer record returned by `noble_getPeerMemory`.
#[derive(Debug, Clone, Serialize)]
pub struct PeerRecordResponse {
    pub identity_key: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub connection_count: u32,
    pub peer_id: String,
    pub last_addr: Option<String>,
    pub node_name: Option<String>,
    pub org_type: Option<String>,
    pub node_role: Option<String>,
    pub host_address: Option<String>,
    pub country_code: Option<String>,
    pub wants_to_validate: bool,
    pub wants_to_vote: bool,
}

/// Reputation score breakdown for a validator (S15-A).
#[derive(Debug, Clone, Serialize)]
pub struct ReputationBreakdown {
    pub block_acceptance_rate: f64,
    pub uptime: f64,
    pub trust_score: f64,
}

/// A single validator entry in the response.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorEntry {
    pub public_key: String,
    pub name: Option<String>,
    pub status: String,
    pub weight: u64,
    pub reputation_score: f64,
    pub reputation_breakdown: ReputationBreakdown,
    pub blocks_produced: u64,
    pub blocks_accepted: u64,
    pub cycles_active: u64,
    pub cycles_reachable: u64,
    pub total_cycles: u64,
    pub last_active: Option<u64>,
    pub joined_cycle: Option<u64>,
    /// Multiaddr from peer announcement (e.g. `/ip4/1.2.3.4/tcp/8780`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_address: Option<String>,
    /// ISO 3166-1 alpha-3 country code from peer announcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

/// Response for `noble_getValidatorList`.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorListResponse {
    pub selection_policy: String,
    pub validators: Vec<ValidatorEntry>,
    pub count: usize,
    /// Operator-defined priority order (hex-encoded wire key bytes).
    pub priority_order: Vec<String>,
}

/// Response for `noble_getCycleStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct CycleStatusResponse {
    pub cycle_number: u64,
    pub phase: String,
    pub phase_index: u8,
    pub phase_remaining_secs: u64,
    pub cycle_remaining_secs: u64,
}

/// Response for `noble_getAddressBalance`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressBalanceResponse {
    pub public_key: String,
    pub balance: u64,
    pub available: u64,
    pub pending: u64,
    pub tx_count: u64,
}

/// Response for `noble_getAddressHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressHistoryResponse {
    pub public_key: String,
    pub transactions: Vec<String>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

/// Response for `noble_getWalletInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletInfoResponse {
    pub unlocked: bool,
    pub expires_at: Option<u64>,
    pub key_count: usize,
    pub balance: u64,
    pub available: u64,
    pub pending: u64,
    /// Balance held in Noble (Ed25519/secp256k1) address buckets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noble_balance: Option<u64>,
    /// Balance held in Bitcoin Hash160 (P2PKH/P2WPKH) address buckets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash160_balance: Option<u64>,
    /// Balance held in Bitcoin Taproot (P2TR) address buckets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taproot_balance: Option<u64>,
}

/// Response for `noble_getNodeInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfoResponse {
    pub version: String,
    /// Alias for `version` — used by the GUI.
    pub software_version: String,
    pub protocol_version: u16,
    pub chain_id: u32,
    /// Network name: "mainnet", "testnet", or "regtest".
    pub network_name: String,
    /// Hex-encoded genesis block hash for chain identity.
    pub genesis_hash: String,
    pub uptime_secs: u64,
    pub rpc_port: u16,
    pub ws_port: u16,
    pub p2p_port: u16,
    /// Base58btc-encoded libp2p PeerId of this node.
    pub peer_id: String,
    /// Highest software version seen on the P2P network, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_network_version: Option<String>,
    /// Total bytes used by the data directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_bytes: Option<u64>,
    /// Total capacity of the disk containing the data directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_capacity_bytes: Option<u64>,
    /// Path to the data directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    /// Hex-encoded validator public key, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
}

/// Response for `noble_getApiVersion`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiVersionResponse {
    pub version: String,
    pub methods: u32,
}

/// Response for `noble_getTlsFingerprint`.
#[derive(Debug, Clone, Serialize)]
pub struct TlsFingerprintResponse {
    /// SHA-256 fingerprint of the active TLS certificate (hex), or null when TLS is disabled.
    pub fingerprint: Option<String>,
}

/// Response for `noble_getTlsCertInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct TlsCertInfoResponse {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// SHA-256 fingerprint (hex), or null when TLS is disabled.
    pub fingerprint: Option<String>,
    /// ISO 8601 expiry timestamp (`not_after`), or null when TLS is disabled.
    pub expires_at: Option<String>,
    /// Days remaining until expiry (negative = already expired), or null when TLS is disabled.
    pub days_remaining: Option<i64>,
    /// Subject Alternative Names of the active certificate.
    pub sans: Vec<String>,
    /// True when the certificate was generated by the node (self-signed).
    pub auto_generated: bool,
    /// True when the node is running in plaintext HTTP fallback mode.
    pub plaintext_mode: bool,
}

/// Response for `noble_regenerateTlsCert`.
#[derive(Debug, Clone, Serialize)]
pub struct RegenerateTlsCertResponse {
    /// New SHA-256 fingerprint (hex).
    pub fingerprint: String,
    /// New ISO 8601 expiry timestamp.
    pub expires_at: String,
    /// Always true — restart node to load the new certificate.
    pub restart_required: bool,
}

/// Response for `noble_uploadTlsCert`.
#[derive(Debug, Clone, Serialize)]
pub struct UploadTlsCertResponse {
    /// SHA-256 fingerprint of the uploaded certificate (hex).
    pub fingerprint: String,
    /// ISO 8601 expiry timestamp of the uploaded certificate.
    pub expires_at: String,
    /// Subject Alternative Names of the uploaded certificate.
    pub sans: Vec<String>,
    /// Always false — uploaded cert is CA-signed (not auto-generated).
    pub auto_generated: bool,
    /// Always true — restart node to load the new certificate.
    pub restart_required: bool,
}

/// Response for `noble_createAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAddressResponse {
    pub address: String,
    pub scheme_id: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bitcoin_addresses: Vec<BitcoinAddressEntry>,
}

/// Response for `noble_walletUnlock`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletUnlockResponse {
    pub unlocked: bool,
    pub expires_at: u64,
}

/// A single entry in a batch submission result.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResultEntry {
    pub checksum: String,
    pub tx_id: Option<String>,
    pub error: Option<String>,
}

/// Response for `noble_submitDocumentBatch`.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitBatchResponse {
    pub results: Vec<BatchResultEntry>,
    pub accepted: usize,
    pub rejected: usize,
}

/// Response for `noble_validateAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct ValidateAddressResponse {
    pub valid: bool,
    pub scheme_id: Option<u8>,
    /// Address type: "ed25519", "secp256k1", "bitcoin_hash160", "bitcoin_taproot"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
}

/// Response for `noble_getTransactionStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionStatusResponse {
    pub tx_id: String,
    pub status: String,
}

/// Response for `noble_getTransactionReceipt`.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionReceiptResponse {
    pub transaction: TransactionResponse,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub tx_index: Option<u32>,
    pub confirmations: Option<u64>,
}

/// Response for `noble_verifyDocument`.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyDocumentResponse {
    pub checksum: String,
    pub registered: bool,
    pub registrations: Vec<RegistrationRecord>,
    pub first_seen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_chain: Option<Vec<VersionEntry>>,
}

/// Response for `noble_getDocumentHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentHistoryResponse {
    pub checksum: String,
    pub history: Vec<RegistrationRecord>,
}

/// A single entry in a document version chain.
#[derive(Debug, Clone, Serialize)]
pub struct VersionEntry {
    pub checksum: String,
    pub tx_id: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub version: Option<u32>,
}

/// Response for `noble_getDocumentVersions`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentVersionsResponse {
    pub root_checksum: String,
    pub versions: Vec<VersionEntry>,
    pub count: usize,
}

/// A single document record returned by publisher search.
#[derive(Debug, Clone, Serialize)]
pub struct PublisherDocumentRecord {
    pub tx_id: String,
    pub checksum: String,
    pub block_height: u64,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// Response for `noble_getDocumentsByPublisher`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentsByPublisherResponse {
    pub publisher: String,
    pub documents: Vec<PublisherDocumentRecord>,
    pub count: usize,
}

/// Response for `noble_getReputationScore` (placeholder).
#[derive(Debug, Clone, Serialize)]
pub struct ReputationScoreResponse {
    pub pubkey: String,
    pub score: f64,
    pub breakdown: ReputationBreakdown,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub votes_cast: u64,
    pub votes_missed: u64,
    pub uptime_cycles: u64,
    pub total_cycles: u64,
}

/// Response for `noble_rotateTotpSecret`.
#[derive(Debug, Clone, Serialize)]
pub struct RotateTotpResponse {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

/// Response for `noble_decryptLocator`.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptLocatorResponse {
    pub tx_id: String,
    pub plaintext: String,
}

/// Response for `noble_generateMnemonic`.
#[derive(Debug, Clone, Serialize)]
pub struct GenerateMnemonicResponse {
    pub mnemonic: String,
    pub address: String,
    pub scheme_id: u8,
    pub word_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_addresses: Option<Vec<BitcoinAddressEntry>>,
}

/// Response for `noble_importMnemonic`.
#[derive(Debug, Clone, Serialize)]
pub struct ImportMnemonicResponse {
    pub address: String,
    pub scheme_id: u8,
    pub already_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_addresses: Option<Vec<BitcoinAddressEntry>>,
}

/// Response for `noble_getVotingStrategy`.
#[derive(Debug, Clone, Serialize)]
pub struct VotingStrategyResponse {
    /// Strategy name for Round 1 (Reflection): first_valid, fixed_validator, etc.
    pub round1_strategy: String,
    /// Optional parameters for Round 1 strategy (e.g. validator_key for fixed_validator).
    pub round1_params: serde_json::Value,
    /// Strategy name for Round 2 (Confirmation).
    pub round2_strategy: String,
    /// Optional parameters for Round 2 strategy.
    pub round2_params: serde_json::Value,
}

/// A single entry in the vote tally.
#[derive(Debug, Clone, Serialize)]
pub struct VoteTallyEntry {
    pub block_hash: String,
    pub vote_count: usize,
}

/// Response for `noble_getVoteTallies`.
#[derive(Debug, Clone, Serialize)]
pub struct VoteTalliesResponse {
    pub cycle: u64,
    pub phase: String,
    pub tallies: Vec<VoteTallyEntry>,
}

/// Ban reason response for peer info.
#[derive(Debug, Clone, Serialize)]
pub struct BanReasonResponse {
    pub category: String,
    pub subject: String,
}

/// A single cycle history entry in the getCycleHistory response.
#[derive(Debug, Clone, Serialize)]
pub struct CycleHistoryEntryResponse {
    pub cycle_number: u64,
    pub status: String,
    pub proposals: Vec<CycleHistoryProposal>,
    pub votes: Vec<CycleHistoryVote>,
    pub winner: Option<String>,
    pub winning_hash: Option<String>,
    pub disambiguation: bool,
    pub finalized_at: u64,
}

/// A proposal within a cycle history entry.
#[derive(Debug, Clone, Serialize)]
pub struct CycleHistoryProposal {
    pub validator: String,
    pub block_hash: String,
    pub tx_count: u32,
}

/// A vote tally within a cycle history entry.
#[derive(Debug, Clone, Serialize)]
pub struct CycleHistoryVote {
    pub block_hash: String,
    pub validator: String,
    pub vote_count: usize,
}

/// Response for `noble_getCycleHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct CycleHistoryResponse {
    pub entries: Vec<CycleHistoryEntryResponse>,
    pub count: usize,
}

/// Response for `noble_getAllowedIps`.
#[derive(Debug, Clone, Serialize)]
pub struct AllowedIpsResponse {
    pub allowed_ips: Vec<String>,
    pub remote_access_enabled: bool,
}

/// Response for `noble_setAllowedIps`.
#[derive(Debug, Clone, Serialize)]
pub struct SetAllowedIpsResponse {
    pub success: bool,
    pub message: String,
}

/// Response for `noble_getGatewayInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayInfoResponse {
    /// Whether gateway fee split is active.
    pub enabled: bool,
    /// Hex-encoded wire public key of the gateway (if set).
    pub gateway_key: Option<String>,
    /// Source of the key: "config_file", "wallet_auto", or "none".
    pub key_source: String,
}

/// Response for `noble_rotateGatewayKey`.
#[derive(Debug, Clone, Serialize)]
pub struct RotateGatewayKeyResponse {
    /// Success indicator.
    pub success: bool,
    /// Hex-encoded wire bytes of the new gateway key.
    pub new_gateway_key: String,
    /// Whether the key was persisted to disk.
    pub persisted: bool,
}

/// Response for `noble_getStorageInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageInfoResponse {
    pub chain_height: u64,
    pub pruning_mode: String,
    pub keep_blocks: u64,
    pub pruned_up_to: u64,
    pub lowest_full_height: u64,
}

/// Response for `noble_setStorageMode`.
#[derive(Debug, Clone, Serialize)]
pub struct SetStorageModeResponse {
    pub success: bool,
    pub previous_mode: String,
    pub new_mode: String,
    pub message: String,
}

/// Response for `noble_getPruningStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct PruningStatusResponse {
    pub mode: String,
    pub blocks_pruned: u64,
    pub transactions_removed: u64,
    pub lowest_full_height: u64,
    pub more_remaining: bool,
}

/// A single column family entry in the storage stats response.
#[derive(Debug, Clone, Serialize)]
pub struct CfStatsEntry {
    pub name: String,
    pub estimated_bytes: u64,
    pub estimated_keys: u64,
}

/// Response for `noble_getStorageStats`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageStatsResponse {
    pub data_dir: Option<String>,
    pub total_db_bytes: u64,
    pub available_bytes: u64,
    pub total_volume_bytes: u64,
    pub cache_size_bytes: u64,
    pub compression_enabled: bool,
    pub column_families: Vec<CfStatsEntry>,
    /// Maximum database size in bytes. 0 = unlimited.
    pub max_db_size_bytes: u64,
}

/// Response for `noble_getStorageConfig`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageConfigResponse {
    pub data_dir: String,
    pub cache_size_mb: u32,
    pub compression: bool,
    pub pruning_mode: String,
    pub keep_blocks: u64,
    pub max_db_size_gb: u64,
}

/// Response for `noble_getSetupStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatusResponse {
    pub setup_complete: bool,
}

/// Response for `noble_getNodeIdentity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentityResponse {
    pub node_name: String,
    pub org_type: String,
    pub org_name: String,
    pub node_role: String,
    pub contact_email: String,
    pub website: String,
    pub host_address: String,
    pub wants_to_validate: bool,
    pub wants_to_vote: bool,
    pub p2p_port: u16,
    pub country_code: String,
}

/// Response for `noble_setNodeIdentity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNodeIdentityResponse {
    pub success: bool,
    /// Hex-encoded wire pubkey of the auto-generated (or existing) validator key.
    /// Only present when `wants_to_validate = true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
}

/// A derived Bitcoin display address for a secp256k1 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinAddressEntry {
    /// Address type: `"p2pkh"`, `"p2wpkh"`, or `"p2tr"`.
    pub address_type: String,
    /// The Bitcoin address string (`1...`, `bc1q...`, or `bc1p...`).
    pub address: String,
}

/// A single wallet key entry returned by `noble_listAddresses`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletKeyEntry {
    /// Wire-format hex-encoded public key.
    pub pubkey_hex: String,
    /// Signature scheme: `"ed25519"` or `"secp256k1"`.
    pub scheme: String,
    /// Derived Bitcoin display addresses (secp256k1 keys only).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bitcoin_addresses: Vec<BitcoinAddressEntry>,
}

/// Response for `noble_listAddresses`.
#[derive(Debug, Clone, Serialize)]
pub struct ListAddressesResponse {
    pub keys: Vec<WalletKeyEntry>,
}

/// Response for `noble_getValidatorKeyInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorKeyInfoResponse {
    /// Whether this node is running in validator mode.
    pub enabled: bool,
    /// Hex-encoded wire pubkey (scheme_id + 32 bytes), if enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_hex: Option<String>,
    /// Signature scheme string, if enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// File path of the validator key, if enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

/// Response for `noble_enableTotp`.
#[derive(Debug, Clone, Serialize)]
pub struct EnableTotpResponse {
    /// The base32-encoded TOTP shared secret.
    pub secret_base32: String,
    /// An `otpauth://` URI for QR code generation.
    pub otpauth_uri: String,
}

/// Response for `noble_getTotpStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct TotpStatusResponse {
    /// Whether TOTP authentication is currently enabled.
    pub enabled: bool,
    /// Enforcement scope: "all", "write_only", or "none".
    pub scope: String,
}

/// Response for `noble_setRewardAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct SetRewardAddressResponse {
    /// The detected address type: "bitcoin_hash160", "bitcoin_taproot", "ed25519", "secp256k1".
    pub address_type: String,
    /// Human-readable display address.
    pub display_address: String,
    /// Hex-encoded wire bytes used as the balance DB key.
    pub wire_hex: String,
}

/// Response for `noble_getRewardAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct GetRewardAddressResponse {
    /// Whether a reward address is configured.
    pub configured: bool,
    /// The configured reward address string (as entered by the operator).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Detected address type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
    /// Hex-encoded wire bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_hex: Option<String>,
}

/// Response for `noble_importSecp256k1Key`.
#[derive(Debug, Clone, Serialize)]
pub struct ImportKeyResponse {
    /// Hex-encoded wire bytes of the imported public key.
    pub public_key: String,
    /// Derived Bitcoin P2WPKH address (bc1q...) for this key.
    pub bitcoin_address: String,
    /// All derived Bitcoin display addresses.
    pub bitcoin_addresses: Vec<BitcoinAddressEntry>,
}

/// Response for `noble_deleteAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteAddressResponse {
    pub success: bool,
    pub message: String,
}

/// Response for `noble_setConfigValue`.
#[derive(Debug, Clone, Serialize)]
pub struct SetConfigValueResponse {
    /// Whether the config was successfully updated.
    pub success: bool,
    /// Whether a node restart is required for the change to take effect.
    pub restart_required: bool,
}

/// Response for `noble_checkDataDir`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckDataDirResponse {
    /// Whether the path exists.
    pub exists: bool,
    /// Whether the path is writable.
    pub writable: bool,
    /// Available disk space in bytes.
    pub available_bytes: u64,
    /// Error message if any check failed.
    pub error: Option<String>,
}

/// Response for `noble_getEncryptionStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct EncryptionStatusResponse {
    /// Current encryption mode: "automatic" or "manual".
    pub mode: String,
    /// Whether the `.chain_meta` file exists in the data directory.
    pub chain_meta_exists: bool,
    /// Whether the `.chain_meta` file is password-locked (NBLK format).
    pub is_locked: bool,
}

/// Response for `noble_dialPeer`.
#[derive(Debug, Clone, Serialize)]
pub struct DialPeerResponse {
    pub success: bool,
    pub message: String,
}

/// Response for `noble_getSeeds` / `noble_addSeed` / `noble_removeSeed`.
#[derive(Debug, Clone, Serialize)]
pub struct SeedsResponse {
    pub seeds: Vec<String>,
}

/// Response for `noble_detectExternalIp`.
#[derive(Debug, Clone, Serialize)]
pub struct DetectIpResponse {
    /// The detected external IP address.
    pub ip: String,
    /// Full multiaddr string (e.g. "/ip4/1.2.3.4/tcp/8780").
    pub multiaddr: String,
    /// The URL of the service that provided the IP.
    pub source: String,
}

/// Response for `noble_setEncryptionMode`.
#[derive(Debug, Clone, Serialize)]
pub struct SetEncryptionModeResponse {
    /// Whether the mode switch succeeded.
    pub success: bool,
    /// Whether a node restart is required for the change to take effect.
    pub restart_required: bool,
    /// Human-readable status message.
    pub message: String,
}

/// Response for `noble_getDetectedForks`.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedForksResponse {
    /// Local chain height.
    pub local_height: u64,
    /// Local chain tip hash (hex).
    pub local_tip: String,
    /// Detected fork groups from connected peers.
    pub forks: Vec<ForkEntry>,
}

/// A single fork group detected from connected peers.
#[derive(Debug, Clone, Serialize)]
pub struct ForkEntry {
    /// Tip hash shared by peers in this group (hex).
    pub tip_hash: String,
    /// Chain height at this tip.
    pub height: u64,
    /// Number of peers on this fork.
    pub peers: usize,
    /// Whether this matches the local chain's tip.
    pub is_local: bool,
}

/// Response for `noble_resetChain`.
#[derive(Debug, Clone, Serialize)]
pub struct ResetChainResponse {
    /// Whether the reset succeeded.
    pub reset: bool,
    /// Chain height before the reset.
    pub previous_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_hex_works() {
        let all_zeros = Hash256::ZERO;
        let hex = hash_to_hex(&all_zeros);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));

        let bytes = [0xab; 32];
        let h = Hash256::from_bytes(bytes);
        assert_eq!(hash_to_hex(&h), "ab".repeat(32));
    }

    #[test]
    fn parse_hash_valid() {
        // 64 hex chars = 32 bytes
        let hex_str = "ab".repeat(32);
        let result = parse_hash(&hex_str);
        assert!(result.is_ok());
        let h = result.unwrap();
        assert_eq!(h.as_bytes(), &[0xab; 32]);
    }

    #[test]
    fn parse_pubkey_valid_ed25519() {
        // Generate a valid ed25519 pubkey hex via wire format: scheme_id(1) + 32 bytes
        let mut wire = vec![0x01]; // Ed25519 scheme_id
        wire.extend_from_slice(&[0xAB; 32]);
        let hex_str = hex::encode(&wire);
        let result = parse_pubkey(&hex_str);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_pubkey_invalid_hex() {
        let result = parse_pubkey("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_pubkey_invalid_wire_bytes() {
        // Valid hex but not a valid public key encoding
        let result = parse_pubkey("0102");
        assert!(result.is_err());
    }

    #[test]
    fn parse_hash_invalid() {
        // Non-hex characters
        let result = parse_hash("gg00");
        assert!(result.is_err());

        // Wrong length (31 bytes = 62 hex chars)
        let short_hex = "ab".repeat(31);
        let result = parse_hash(&short_hex);
        assert!(result.is_err());

        // Empty string
        let result = parse_hash("");
        assert!(result.is_err());
    }

    #[test]
    fn block_response_serializes() {
        let br = BlockResponse {
            height: 42,
            hash: "aa".repeat(32),
            prev_hash: "bb".repeat(32),
            merkle_root: "cc".repeat(32),
            timestamp: 1700000000,
            tx_count: 3,
            validator_id: "dd".repeat(16),
            transactions: vec![],
        };

        let json_str = serde_json::to_string(&br).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json_str).expect("not valid JSON");
        assert_eq!(v["height"], 42);
        assert_eq!(v["tx_count"], 3);
        assert_eq!(v["timestamp"], 1700000000u64);
        assert!(v["transactions"].as_array().unwrap().is_empty());
    }
}
