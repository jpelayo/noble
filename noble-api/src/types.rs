// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-serializable response structs for the NOBLE RPC API.

use jsonrpsee::types::ErrorObjectOwned;
use serde::Serialize;

use noble_core::{Block, Transaction};
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

/// Response for `noble_lookupChecksum`.
#[derive(Debug, Clone, Serialize)]
pub struct ChecksumLookupResponse {
    pub checksum: String,
    pub registrations: Vec<String>,
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
    pub connected_at: u64,
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
    pub wants_to_validate: bool,
    pub wants_to_vote: bool,
}

/// A single validator entry in the response.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorEntry {
    pub public_key: String,
    pub name: Option<String>,
    pub status: String,
    pub weight: u64,
    pub reputation_score: f64,
    pub blocks_produced: u64,
    pub cycles_active: u64,
    pub last_active: Option<u64>,
    pub joined_cycle: Option<u64>,
}

/// Response for `noble_getValidatorList`.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorListResponse {
    pub selection_policy: String,
    pub validators: Vec<ValidatorEntry>,
    pub count: usize,
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
}

/// Response for `noble_getNodeInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfoResponse {
    pub version: String,
    pub protocol_version: u16,
    pub chain_id: u32,
    pub uptime_secs: u64,
    pub rpc_port: u16,
    pub ws_port: u16,
    pub p2p_port: u16,
}

/// Response for `noble_createAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateAddressResponse {
    pub address: String,
    pub scheme_id: u8,
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
    pub found: bool,
    pub registration_count: usize,
}

/// Response for `noble_getDocumentHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentHistoryResponse {
    pub checksum: String,
    pub transactions: Vec<TransactionResponse>,
}

/// Response for `noble_getReputationScore` (placeholder).
#[derive(Debug, Clone, Serialize)]
pub struct ReputationScoreResponse {
    pub pubkey: String,
    pub score: u64,
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
}

/// Response for `noble_importMnemonic`.
#[derive(Debug, Clone, Serialize)]
pub struct ImportMnemonicResponse {
    pub address: String,
    pub scheme_id: u8,
    pub already_exists: bool,
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
