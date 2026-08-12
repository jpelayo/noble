// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-serializable response structs for the NOBLE RPC API.

use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

use noble_core::{Block, NobleAddress, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

fn is_zero(v: &u64) -> bool { *v == 0 }

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a `Hash256` to a lowercase hex string.
pub fn hash_to_hex(h: &Hash256) -> String {
    hex::encode(h.as_bytes())
}

/// Parse a hex-encoded wire-format public key, returning a JSON-RPC error on failure.
/// Accepts Noble wire format (0x02 scheme prefix + 33 bytes) or raw 33-byte compressed key (0x02/0x03 SEC1 prefix).
pub fn parse_pubkey(input: &str) -> Result<NoblePublicKey, ErrorObjectOwned> {
    let trimmed = input.trim();
    // Try nbl1… bech32 address first
    if noble_crypto::noble_addr::is_noble_address(trimmed) {
        return noble_crypto::noble_addr::decode(trimmed)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()).into());
    }
    // Fall back to hex bytes — gate length to prevent OOM (C2 audit fix).
    // Max Noble wire key is 35 bytes (scheme_id + 34 bytes) → 70 hex chars.
    if trimmed.len() > 256 {
        return Err(ApiError::InvalidAddress("input too long".into()).into());
    }
    let bytes =
        hex::decode(trimmed).map_err(|_| ApiError::InvalidAddress("invalid hex string".into()))?;
    // Try Noble wire format first (scheme_id prefix + key)
    if let Ok(pk) = NoblePublicKey::from_wire_bytes(&bytes) {
        return Ok(pk);
    }
    // Fallback: raw 33-byte compressed secp256k1 key (0x02 or 0x03 SEC1 prefix)
    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        return Ok(NoblePublicKey::Secp256k1(bytes));
    }
    Err(ApiError::InvalidAddress("not a valid public key".into()).into())
}

/// Parse an address string into a `NobleAddress`.
///
/// Accepts:
/// - Noble native addresses: `nbl1p…` (secp256k1 bech32m)
/// - Hex-encoded wire-format NOBLE public keys (secp256k1: 0x02)
/// - Bitcoin addresses: P2PKH (1...), P2WPKH (bc1q...), P2TR (bc1p...)
/// - Hex-encoded Bitcoin address wire bytes (0x80, 0x81 prefix)
pub fn parse_address(input: &str) -> Result<NobleAddress, ErrorObjectOwned> {
    let trimmed = input.trim();

    // Try Noble native address format (nbl1q…, nbl1p…)
    if noble_crypto::noble_addr::is_noble_address(trimmed) {
        let pk = noble_crypto::noble_addr::decode(trimmed)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;
        return Ok(NobleAddress::Noble(pk));
    }

    // Try Bitcoin address formats (bc1q..., bc1p..., 1..., tb1...)
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
    // Gate length to prevent OOM (C2 audit fix).
    if trimmed.len() > 256 {
        return Err(ApiError::InvalidAddress("input too long".into()).into());
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| ApiError::InvalidAddress("invalid hex string or unrecognized address format".into()))?;
    // Try Noble wire format first (scheme_id + key or Bitcoin address wire)
    if let Ok(addr) = NobleAddress::from_wire_bytes(&bytes) {
        return Ok(addr);
    }
    // Fallback: raw 33-byte compressed secp256k1 key (0x02 or 0x03 SEC1 prefix)
    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        return Ok(NobleAddress::Noble(NoblePublicKey::Secp256k1(bytes)));
    }
    Err(ApiError::InvalidAddress("not a valid address or public key".into()).into())
}

/// Parse a hex string into a `Hash256`, returning a JSON-RPC error on failure.
pub fn parse_hash(hex_str: &str) -> Result<Hash256, ErrorObjectOwned> {
    // Gate length — a Hash256 is 32 bytes = 64 hex chars (C2 audit fix).
    if hex_str.len() > 128 {
        return Err(ApiError::InvalidAddress("hash hex too long".into()).into());
    }
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
    // Genesis is committed with chain_id = 0: the id is derived from the
    // genesis hash, so genesis cannot commit to it. Use 0 for genesis so the
    // tx_ids we return match what is stored in CF_TX_INDEX.
    //
    // This used to read `height <= 1`, covering both the empty index 0 and the
    // block that was then genesis. With genesis at its own index the test is
    // exact — and `<= 1` would now silently mis-report block 1's tx_ids.
    let effective_chain_id = if block.header.height == noble_core::GENESIS_HEIGHT {
        0
    } else {
        chain_id
    };
    let txs: Vec<TransactionResponse> = block
        .transactions
        .iter()
        .map(|tx| {
            let tx_id = tx
                .compute_tx_id(effective_chain_id)
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
        validator_id: block.header.validator_id.to_address(),
        validator_name: None, // Populated by caller via resolve_friendly_name
        transactions: txs,
    }
}

/// Compute confirmation status from confirmation count (1-based, Bitcoin-compatible).
///
/// Status lifecycle:
/// - **pending**: in mempool, no confirmations (`None`)
/// - **admitted**: in a proposed block, not yet committed (`Some(0)`)
/// - **maturing**: in committed chain, 1 to COINBASE_MATURITY confirmations (`Some(1..=3)`)
/// - **complete**: in committed chain, > COINBASE_MATURITY confirmations (`Some(4+)`)
///
/// With 1-based counting, a tx in the latest committed block has 1 confirmation.
/// UTXO is spendable when `creation_height + COINBASE_MATURITY <= current_height`,
/// which corresponds to > COINBASE_MATURITY confirmations (1-based).
pub fn confirmation_status_label(confirmations: Option<u64>) -> String {
    match confirmations {
        None => "pending".to_string(),
        Some(0) => "admitted".to_string(),
        Some(c) if c <= noble_core::COINBASE_MATURITY => "maturing".to_string(),
        Some(_) => "complete".to_string(),
    }
}

/// Convert a `Transaction` to a `TransactionResponse`.
/// Compute the net transfer value for a transaction: sum of outputs NOT going
/// back to the signer. For self-transfers (all outputs to signer) and coinbase,
/// returns total_output_value. Single source of truth — used by tx_to_response
/// and mempool RPC.
pub fn compute_transfer_value(tx: &Transaction) -> u64 {
    let signer_wire: Option<Vec<u8>> = tx.issuer_sig.to_noble_public_key()
        .ok()
        .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes());
    match &signer_wire {
        Some(sw) if !tx.is_coinbase() => {
            let non_signer: u64 = tx.outputs.iter()
                .filter(|o| o.address.to_wire_bytes() != *sw)
                .map(|o| o.value)
                .sum();
            if non_signer == 0 { tx.total_output_value() } else { non_signer }
        }
        _ => tx.total_output_value(),
    }
}

pub fn tx_to_response(tx: &Transaction, tx_id: &str) -> TransactionResponse {
    let has_locator = tx.encrypted_locator.is_some();
    let locator_recipients = tx
        .encrypted_locator
        .as_ref()
        .map_or(0, |l| l.recipients.len());

    let signer_wire: Option<Vec<u8>> = tx.issuer_sig.to_noble_public_key()
        .ok()
        .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes());
    let transfer_value = compute_transfer_value(tx);

    // Recipient: the intended destination address for transfers.
    // Non-signer output = recipient. Self-transfer fallback: signer address.
    let recipient = if tx.tx_type == noble_core::TX_TYPE_TRANSFER {
        let dest = match &signer_wire {
            Some(sw) => tx.outputs.iter()
                .find(|o| o.address.to_wire_bytes() != *sw)
                .or_else(|| tx.outputs.first()),
            _ => tx.outputs.first(),
        };
        dest.map(|o| o.address.to_display_address())
    } else {
        None
    };

    // Privacy: strip input hashes for transfers — exposes UTXO history unnecessarily.
    // Non-transfer types (coinbase, notarization) have 1-2 inputs and are non-sensitive.
    let is_transfer = tx.tx_type == noble_core::TX_TYPE_TRANSFER;
    let input_count = tx.inputs.len() as u32;

    TransactionResponse {
        tx_id: tx_id.to_string(),
        tx_type: tx.tx_type,
        checksum: hash_to_hex(&tx.checksum),
        timestamp: tx.timestamp,
        total_output: tx.total_output_value(),
        transfer_value,
        fee: None, // Set by caller when UTXO data is available
        input_count,
        inputs: if is_transfer {
            vec![]
        } else {
            tx.inputs.iter().map(|i| TxInputResponse {
                txid: hash_to_hex(&i.prev_output.txid),
                vout: i.prev_output.vout,
                value: None,   // resolved by resolve_inputs_and_fee (needs storage)
                address: None,
            }).collect()
        },
        outputs: tx.outputs.iter().map(|o| TxOutputResponse {
            value: o.value,
            address: o.address.to_display_address(),
        }).collect(),
        // Parity-safe: the envelope holds a RAW 33-byte SEC1 key whose first
        // byte is 0x02 (even Y) or 0x03 (odd Y). encode_wire_bytes gates on
        // 0x02 == SCHEME_SECP256K1, so odd-Y keys fell through to hex —
        // to_noble_public_key keys off scheme_id and handles both parities.
        signer: tx.issuer_sig.to_noble_public_key()
            .ok()
            .map(|pk| pk.to_address())
            .unwrap_or_else(|| hex::encode(&tx.issuer_sig.public_key)),
        signer_name: None,   // Populated by caller via resolve_friendly_name
        recipient,
        metadata: tx
            .metadata
            .iter()
            .map(|m| MetadataResponse {
                key: m.key.clone(),
                // Return UTF-8 strings directly, hex-encode only binary values
                value: String::from_utf8(m.value.clone())
                    .unwrap_or_else(|_| hex::encode(&m.value)),
            })
            .collect(),
        has_encrypted_locator: has_locator,
        locator_recipient_count: locator_recipients,
        attestation_count: tx.external_attestations.len(),
        confirmation_status: None, // Set by caller based on context
        confirmations: None,       // Set by caller based on chain tip
        // Wallet-enriched fields (set by wallet RPCs, None otherwise)
        direction: None,
        amount: None,
        type_label: None,
        block_height: None,
        status: None,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_name: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_name: Option<String>,
    /// Cycle number this block was committed in (computed from genesis epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle: Option<u64>,
}

/// Transaction response used in blocks and standalone queries (UTXO model).
#[derive(Debug, Clone, Serialize)]
pub struct TransactionResponse {
    pub tx_id: String,
    pub tx_type: u8,
    pub checksum: String,
    pub timestamp: u64,
    /// Total output value (sum of ALL outputs including change).
    pub total_output: u64,
    /// Net transfer value: outputs NOT going back to the signer.
    /// For coinbase: same as total_output. For transfers: excludes change.
    pub transfer_value: u64,
    /// Implicit fee: sum(input UTXO values) - sum(output values).
    /// `None` for coinbase transactions or if input UTXOs are unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
    /// Number of inputs (always present; inputs[] may be empty for transfers — privacy).
    pub input_count: u32,
    /// Inputs: references to spent UTXOs.
    /// Empty for transfer transactions (privacy: hides UTXO history). Use input_count instead.
    pub inputs: Vec<TxInputResponse>,
    /// Outputs: new UTXOs created.
    pub outputs: Vec<TxOutputResponse>,
    pub signer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Intended destination address (transfers only; None for other tx types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub metadata: Vec<MetadataResponse>,
    pub has_encrypted_locator: bool,
    pub locator_recipient_count: usize,
    pub attestation_count: usize,
    pub attestations: Vec<AttestationResponse>,
    /// Lifecycle status: "pending" (mempool), "admitted" (in block, 0 conf),
    /// "maturing" (1-5 conf), "complete" (6+ conf).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_status: Option<String>,
    /// Number of confirmations (None = pending/mempool).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
    // ── Wallet-enriched fields (set by wallet RPCs, None otherwise) ──
    /// Transaction direction from wallet perspective: "incoming" / "outgoing" / "self".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Wallet-perspective display amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Human-readable type name (e.g., "Transfer", "Notarization").
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub type_label: Option<String>,
    /// Block height containing this transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    /// Status string: "pending", "maturing", "complete".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Transaction input response.
#[derive(Debug, Clone, Serialize)]
pub struct TxInputResponse {
    pub txid: String,
    pub vout: u32,
    /// Value of the UTXO this input spends (resolved from the previous tx's
    /// output). `None` when the source tx is pruned/unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Address that owned the spent UTXO. `None` when unresolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Transaction output response.
#[derive(Debug, Clone, Serialize)]
pub struct TxOutputResponse {
    pub value: u64,
    pub address: String,
}

/// External attestation response (protocol-opaque, for display only).
#[derive(Debug, Clone, Serialize)]
pub struct AttestationResponse {
    pub scheme: String,
    pub scope: String,
    pub signer_fingerprint: String,
    pub signature_size: usize,
}

/// Metadata entry response (key + value as UTF-8 string, or hex if binary).
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
    /// Transaction type name (e.g., "Notarization", "Unlocking").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<String>,
    /// `doc:version` metadata value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `doc:prev_checksum` metadata value (hex), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_checksum: Option<String>,
    /// For unlocking txs: the locked tx_id they reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_tx_id: Option<String>,
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
    /// Low fee rate (P25 of mempool) in groats/byte.
    pub low_fee_rate: u64,
    /// Recommended fee rate (P50) in groats/byte.
    pub recommended_fee_rate: u64,
    /// High priority fee rate (P75) in groats/byte.
    pub high_priority_fee_rate: u64,
    /// Lowest min_fee_rate among connected peers (from NodeAnnounce gossip).
    pub network_min_fee_rate: u64,
    /// Median min_fee_rate among connected peers (from NodeAnnounce gossip).
    pub network_median_fee_rate: u64,
    /// This node's own configured minimum fee rate (groats/byte).
    /// Transactions below this rate will be rejected at submission.
    pub local_min_fee_rate: u64,
}

/// Response for `noble_getMempoolInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct MempoolInfoResponse {
    pub count: usize,
    pub total_bytes: usize,
    /// Lowest fee rate in mempool (groats/byte).
    pub min_fee_rate: u64,
    /// Highest fee rate in mempool (groats/byte).
    pub max_fee_rate: u64,
    /// Average fee rate in mempool (groats/byte).
    pub avg_fee_rate: u64,
    /// Recent mempool entries (top 50 by fee rate).
    pub entries: Vec<MempoolEntryResponse>,
    /// Fee rate histogram for chart display.
    pub fee_histogram: Vec<FeeHistogramBucket>,
}

/// A single mempool entry for the live stream.
#[derive(Debug, Clone, Serialize)]
pub struct MempoolEntryResponse {
    pub tx_id: String,
    pub tx_type: u8,
    pub total_output: u64,
    /// Net transfer value: outputs NOT going to the signer (excludes change).
    pub transfer_value: u64,
    pub fee: u64,
    pub fee_rate: u64,
    pub size_bytes: usize,
    pub received_at: u64,
}

/// Fee histogram bucket for the mempool chart.
#[derive(Debug, Clone, Serialize)]
pub struct FeeHistogramBucket {
    pub label: String,
    pub count: usize,
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
    /// Accumulated misbehavior category codes (wire-stable IDs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub misbehavior_categories: Vec<String>,
    pub last_ban_reason: Option<BanReasonResponse>,
    /// Connection status: "connected" or "disconnected".
    pub status: String,
    /// Peer's ADVERTISED chain tip height (from last status exchange).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_tip_height: Option<u64>,
    /// Highest height VERIFIED from this peer (blocks they served that
    /// validated + committed). K3-04.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_height: Option<u64>,
    /// Peer's chain tip hash (from last status exchange).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_tip_hash: Option<String>,
    /// Round-trip latency in milliseconds (from libp2p ping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Response for `noble_getNetworkInfo`.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInfoResponse {
    pub peer_count: usize,
    pub inbound: usize,
    pub outbound: usize,
    /// Configured maximum connected peers.
    pub max_peers: u32,
    /// Median clock offset across peers (ms, positive = peers ahead).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_offset_ms: Option<i64>,
}

/// Response for `noble_getSyncStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatusResponse {
    pub synced: bool,
    pub current_height: u64,
    pub highest_known: u64,
    pub progress: f64,
    /// Authoritative chain phase label, computed once by the node
    /// (`AlignmentState`). Every GUI surface renders this rather than deriving
    /// its own answer — three independent derivations is how a node ended up
    /// showing "CREATING" and "catching up to 197" simultaneously.
    pub state: String,
    /// Severity class for the state ("zero" | "syncing" | "medium" | "high").
    pub severity: String,
    /// Why the node is blocked, when `state == "Blocked"`. Carried with the
    /// state so a page opened after the event still shows the reason.
    pub blocked_reason: Option<String>,
}

/// A persistent peer record returned by `noble_getPeerMemory`.
#[derive(Debug, Clone, Serialize)]
pub struct PeerRecordResponse {
    pub identity_key: String,
    /// Hex-encoded wire bytes of the identity key (for matching cycle history entries).
    pub identity_key_hex: String,
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
    /// Minimum fee rate (groats/byte) from NodeAnnounce gossip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_fee_rate: Option<u64>,
}

/// A discovered faucet on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetEntry {
    pub url: String,
    pub faucet_address: String,
    pub faucet_balance: u64,
    pub drip_amount: u64,
    pub network: String,
    pub last_probed: u64,
}

/// Thread-safe faucet cache shared between the node (writer) and API (reader).
pub type FaucetCache = std::sync::Arc<parking_lot::Mutex<Vec<FaucetEntry>>>;

/// Response for `noble_getAvailableFaucets`.
#[derive(Debug, Clone, Serialize)]
pub struct AvailableFaucetsResponse {
    pub faucets: Vec<FaucetEntry>,
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
    /// Hex-encoded wire bytes (for matching cycle history entries that use hex keys).
    pub public_key_hex: String,
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
    /// Number of alive validators in the list (trust metric).
    pub listers_count: usize,
    /// Minimum fee rate (groats/byte) from NodeAnnounce gossip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_fee_rate: Option<u64>,
    /// Whether this validator has proposed a block in the current cycle.
    pub proposed_this_cycle: bool,
    /// Whether this peer announced `wants_to_validate = true`.
    /// Defaults to `true` for validators with no announce data (benefit of doubt).
    pub wants_to_validate: bool,
    /// Whether this validator holds an active voting badge.
    pub has_badge: bool,
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
    /// `null` when bootstrapping (no genesis block yet).
    pub cycle_number: Option<u64>,
    pub phase: String,
    pub phase_index: u8,
    pub phase_remaining_secs: u64,
    pub cycle_remaining_secs: u64,
    /// Genesis epoch (block 1 timestamp). `null` before first block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_timestamp: Option<u64>,
}

/// Response for `noble_getAddressBalance`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressBalanceResponse {
    pub public_key: String,
    /// Total on-chain balance (all UTXOs, including immature).
    pub balance: u64,
    /// Spendable right now: mature UTXOs minus net pending debits.
    pub available: u64,
    /// Net pending debit: outputs leaving wallet + fees (NOT gross UTXO consumption).
    pub pending: u64,
    /// Change outputs returning to this address from pending txs (available after confirmation).
    pub pending_change: u64,
    pub tx_count: u64,
    pub utxo_count: usize,
    pub immature_count: usize,
    pub immature_value: u64,
    /// Per-transaction pending breakdown.
    pub pending_transactions: Vec<PendingTxResponse>,
}

/// A single pending transaction's UTXO flow relative to an address.
#[derive(Debug, Clone, Serialize)]
pub struct PendingTxResponse {
    pub tx_id: String,
    pub sent: u64,
    pub change: u64,
    pub fee: u64,
    pub net_debit: u64,
    /// Always "pending" for mempool transactions.
    pub confirmation_status: String,
}

/// Response for `noble_getAddressPending`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressPendingResponse {
    pub address: String,
    pub count: usize,
    pub transactions: Vec<PendingTxResponse>,
}

/// Response for `noble_getAddressUtxos`.
#[derive(Debug, Clone, Serialize)]
pub struct AddressUtxosResponse {
    pub address: String,
    pub utxos: Vec<UtxoResponse>,
    /// Number of UTXOs excluded because they are immature (< COINBASE_MATURITY confirmations).
    pub immature_count: usize,
    /// Total value locked in immature UTXOs (groats).
    pub immature_value: u64,
}

/// A single UTXO in the address UTXO response.
#[derive(Debug, Clone, Serialize)]
pub struct UtxoResponse {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
    pub is_coinbase: bool,
    /// UTXO lifecycle status for client coin selection:
    /// - `"available"`: spendable, mature, not consumed by a pending tx
    /// - `"pending_spend"`: consumed by a pending mempool transaction
    /// - `"immature"`: output not yet mature (< COINBASE_MATURITY confirmations)
    pub status: String,
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
    /// Pending CREDIT (incoming mempool outputs from external senders).
    /// None or omitted means zero / not computed; older clients see no field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_credit: Option<u64>,
    /// Immature UTXO value (depth < COINBASE_MATURITY). Not yet spendable.
    #[serde(skip_serializing_if = "is_zero")]
    pub immature: u64,
    /// Balance held in Noble (secp256k1) address buckets.
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
    /// Chain label (hex chain ID or empty for uninitialized).
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
    /// Path to the noble.toml configuration file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// Hex-encoded validator public key (wire format), if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pubkey: Option<String>,
    /// Bech32 display address (`nbl1q…` / `nbl1p…`) of the validator key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_pubkey_display: Option<String>,
    /// True when the node is catching up blocks from a peer.
    pub sync_behind: bool,
    /// Target height the node is syncing towards (0 when not syncing).
    pub sync_target_height: u64,
    /// Current height during sync (0 when not syncing).
    pub sync_current_height: u64,
    /// Sync progress percentage (0-100, 0 when not syncing).
    pub sync_progress_pct: u64,
    /// Faucet wallet address (bech32m), if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faucet_address: Option<String>,
    /// Whether the faucet server is enabled in config.
    pub faucet_enabled: bool,
    /// Whether the faucet child process is ACTUALLY listening (verified by
    /// the node's supervisor probing the faucet's HTTP endpoint). This is the
    /// liveness truth — `faucet_enabled` is only intent.
    pub faucet_listening: bool,
    /// Faucet listen address (e.g. "0.0.0.0:8786"), if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faucet_listen: Option<String>,
    /// Validator's personal minimum fee rate (groats/byte) for block proposal.
    pub min_fee_rate: u64,
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
    /// Address type: "secp256k1", "bitcoin_hash160", "bitcoin_taproot"
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
    pub tx_id: String,
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

/// A single document record returned by issuer search.
#[derive(Debug, Clone, Serialize)]
pub struct IssuerDocumentRecord {
    pub tx_id: String,
    pub checksum: String,
    pub block_height: u64,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// Response for `noble_getDocumentsByIssuer`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentsByIssuerResponse {
    pub issuer: String,
    pub documents: Vec<IssuerDocumentRecord>,
    pub count: usize,
}

/// Response for `noble_searchDocumentsByMetadata`.
#[derive(Debug, Clone, Serialize)]
pub struct MetadataSearchResponse {
    pub key: String,
    pub value: String,
    pub documents: Vec<IssuerDocumentRecord>,
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

/// Response for `noble_getFaucetAdminToken` and `noble_rotateFaucetAdminToken`.
/// The token gates all faucet HTTP admin endpoints
/// (e.g. `/api/faucet/reset-limits`); the faucet binary fetches it via the
/// `getFaucetAdminToken` RPC and refreshes every 60 seconds.
#[derive(Debug, Clone, Serialize)]
pub struct FaucetAdminTokenResponse {
    /// 64-char hex (32 random bytes) — the bearer value clients send.
    pub token: String,
    /// Wall-clock seconds since UNIX epoch when the token was last rotated.
    pub created_at_unix: u64,
    /// First 8 chars of SHA-256(token) — for log correlation without leaking the token.
    pub fingerprint: String,
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
    /// Validator name (from validator list), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator: Option<String>,
    /// Validator identity key (hex wire bytes), if the block is in the candidate tracker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_key: Option<String>,
    /// Number of transactions in the proposed block (from candidate tracker).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_count: Option<u32>,
    /// R2 (confirmation) vote count, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r2_vote_count: Option<usize>,
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

/// Response for `noble_checkChainIntegrity`.
#[derive(Debug, Clone, Serialize)]
pub struct ChainIntegrityResponse {
    pub heights_checked: u64,
    pub is_clean: bool,
    pub findings_count: usize,
    pub first_corrupt_height: Option<u64>,
    pub findings: Vec<ChainIntegrityFinding>,
}

/// A single finding from the chain integrity check.
#[derive(Debug, Clone, Serialize)]
pub struct ChainIntegrityFinding {
    pub height: u64,
    pub kind: String,
    pub detail: String,
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
    pub r2_vote_count: usize,
}

/// Response for `noble_getCycleHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct CycleHistoryResponse {
    pub entries: Vec<CycleHistoryEntryResponse>,
    pub count: usize,
}

/// Response for `noble_getBlockVotes`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockVotesResponse {
    pub height: u64,
    pub cycle_number: u64,
    pub voter_count: usize,
    pub strength: String,
    pub r1_voters: Vec<BlockVoterResponse>,
    pub r2_voters: Vec<BlockVoterResponse>,
    pub unique_witness_count: usize,
    pub dual_witness_required: bool,
    pub dual_witness_met: bool,
}

/// A single validator's vote in a [`BlockVotesResponse`].
#[derive(Debug, Clone, Serialize)]
pub struct BlockVoterResponse {
    pub validator_key: String,
    pub name: String,
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
}

/// Response for `noble_getStorageConfig`.
#[derive(Debug, Clone, Serialize)]
pub struct StorageConfigResponse {
    pub data_dir: String,
    pub cache_size_mb: u32,
    pub compression: bool,
    pub pruning_mode: String,
    pub keep_blocks: u64,
    /// Operator's DB size target in GB (0 = unlimited; advisory, not enforced).
    pub max_db_size_gb: u32,
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
    /// Bech32-encoded validator public key (nbl1q.../nbl1p...) of the auto-generated (or existing) validator key.
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
    /// Signature scheme: `"secp256k1"`.
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
    /// Bech32m display address (`nbl1p…`), if enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_display: Option<String>,
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

/// Response for `noble_getGuiLockStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct GuiLockStatusResponse {
    /// Whether the GUI admin lock (dashboard session login wall) is enabled.
    pub enabled: bool,
    /// Whether a live TOTP validator exists — the lock can only be enabled when
    /// this is true. The Settings UI disables the toggle and shows "Enable TOTP
    /// first" when this is false.
    pub totp_available: bool,
}

/// Response for `noble_setRewardAddress`.
#[derive(Debug, Clone, Serialize)]
pub struct SetRewardAddressResponse {
    /// The detected address type: "bitcoin_hash160", "bitcoin_taproot", "secp256k1".
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

/// Response for `noble_getLoggingConfig`.
#[derive(Debug, Clone, Serialize)]
pub struct LoggingConfigResponse {
    /// Live maximum total size (bytes) across all rotating log files.
    pub max_size_bytes: u64,
    /// Whether rotating file logging is currently active (cap > 0). When false,
    /// changing the size requires a restart to (re)enable file logging.
    pub file_enabled: bool,
    /// Absolute path the rotating log actually writes to. `None` when file
    /// logging is disabled. Depends on `[logging] file_path` and falls back to
    /// the data dir, so it is not necessarily where packaging docs point.
    pub file_path: Option<String>,
    /// Number of rotating files kept (active + rotated).
    pub max_files: usize,
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
    /// True when the node runs inside a container (Docker/Podman/K8s/LXC).
    pub container: bool,
    /// Whether data written to this path survives a container rebuild.
    /// `None` when undetectable (non-Linux hosts).
    pub durable: Option<bool>,
    /// Filesystem type of the mount governing this path (e.g. "overlay",
    /// "ext4"). Diagnostic only; `None` when undetectable.
    pub mount_fstype: Option<String>,
    /// The best standard data directory for this environment
    /// (`platform_data_dir()`, which honors the container's NOBLE_DATA_DIR).
    pub recommended_dir: String,
    /// Human-readable custody warning; set only when the chosen path is
    /// dangerous (e.g. ephemeral overlay inside a container).
    pub warning: Option<String>,
}

/// A single directory entry for the folder browser.
#[derive(Debug, Clone, Serialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub writable: bool,
}

/// Response for `noble_listDirectory`.
#[derive(Debug, Clone, Serialize)]
pub struct ListDirectoryResponse {
    /// Current directory path.
    pub current: String,
    /// Parent directory path (empty for root).
    pub parent: String,
    /// Directory entries (directories only, sorted).
    pub entries: Vec<DirectoryEntry>,
    /// Error message if the path cannot be read.
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

/// Response for `noble_listBannedPeers`.
#[derive(Debug, Clone, Serialize)]
pub struct BannedPeerResponse {
    pub peer_id: String,
    pub ban_score: u32,
    pub banned_until: u64,
    pub reason_category: String,
    pub reason_subject: String,
    /// All misbehavior category codes that contributed to this ban (e.g. [1, 7]).
    pub reason_codes: Vec<u8>,
    pub node_name: Option<String>,
    /// SHA-256 of the CBOR-encoded evidence (hex), if this ban is evidence-backed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
}

/// Response for `noble_getBadgeHolders`.
#[derive(Debug, Clone, Serialize)]
pub struct BadgeHolderResponse {
    pub pubkey: String,
    pub node_name: Option<String>,
    pub status: String,
    pub granted_at_height: u64,
    pub last_seen: u64,
}

/// Response for `noble_getActiveProposals` / `noble_getProposalHistory`.
#[derive(Debug, Clone, Serialize)]
pub struct BadgeProposalResponse {
    pub proposal_hash: String,
    pub proposal_type: String,
    pub target_pubkey: String,
    pub target_name: Option<String>,
    pub proposer_pubkey: String,
    pub proposer_name: Option<String>,
    pub reason: Option<String>,
    pub created_at_cycle: u64,
    pub expires_at_cycle: u64,
    pub votes_for: u32,
    pub votes_against: u32,
    pub total_eligible_voters: u32,
    pub status: String,
}

/// Response for `noble_getDetectedForks`.
/// Response for DAO poll queries.
#[derive(Debug, Clone, Serialize)]
pub struct DaoPollResponse {
    pub poll_id: String,
    pub question: String,
    pub proposer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposer_name: Option<String>,
    pub created_at_cycle: u64,
    pub expires_at_cycle: u64,
    pub votes_yes: u32,
    pub votes_no: u32,
    pub votes_abstain: u32,
    pub total_eligible: u32,
    pub status: String,
}

/// Convert wire pubkey bytes to bech32m address string.
pub fn wire_to_address(wire: &[u8]) -> String {
    noble_crypto::NoblePublicKey::from_wire_bytes(wire)
        .map(|pk| pk.to_address())
        .unwrap_or_else(|_| hex::encode(wire))
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectedForksResponse {
    /// Local chain height.
    pub local_height: u64,
    /// Local chain tip hash (hex).
    pub local_tip: String,
    /// Number of connected peers reporting chain tip data.
    pub peer_count: usize,
    /// Highest chain height known from any peer.
    pub highest_known: u64,
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
    /// Whether this fork's tip agrees with the local chain at the same height.
    /// `true` = same block hash at this height (same chain, just behind/ahead).
    /// `false` = different block hash (diverged chain).
    /// `None` = cannot verify (height beyond local chain, or lookup error).
    pub agrees_with_local: Option<bool>,
}

/// Response for `noble_resetChain`.
#[derive(Debug, Clone, Serialize)]
pub struct ResetChainResponse {
    /// Whether the reset succeeded.
    pub reset: bool,
    /// Chain height before the reset.
    pub previous_height: u64,
}

/// Response for `noble_getDiscoveredBlockchains`.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredBlockchainsResponse {
    /// Discovered blockchains from peers on other chains.
    pub blockchains: Vec<DiscoveredBlockchainEntry>,
}

/// A blockchain discovered via NodeAnnounce from a peer on a different chain.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredBlockchainEntry {
    /// The chain_id of the discovered blockchain (hex).
    pub chain_id: String,
    /// Human-readable network name.
    pub network_name: String,
    /// Peer addresses that announced this chain.
    pub peer_addresses: Vec<String>,
    /// Timestamp of first discovery.
    pub first_seen: u64,
    /// Timestamp of most recent announcement.
    pub last_seen: u64,
}

/// Runtime info about a discovered blockchain (shared between Node and API).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredBlockchainInfo {
    /// The chain_id of the discovered blockchain.
    pub chain_id: u32,
    /// Chain label (hex chain ID).
    pub network_name: String,
    /// Peer addresses that announced this chain (multiaddr strings).
    pub peer_addresses: Vec<String>,
    /// Timestamp of first discovery.
    pub first_seen: u64,
    /// Timestamp of most recent announcement.
    pub last_seen: u64,
    /// Committed chain tip height reported by peers on this chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_tip_height: Option<u64>,
    /// Cumulative vote weight across all blocks (legitimacy indicator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_vote_weight: Option<u64>,
}

/// Response for `noble_getWalletTransactions`.
#[derive(Debug, Clone, Serialize)]
pub struct WalletTransactionsResponse {
    pub transactions: Vec<TransactionResponse>,
}

/// Atomic wallet snapshot: balance + transactions computed under a single
/// storage read lock. Guarantees `chain_height` is identical for both the
/// balance/immature classification and the confirmation counts on transactions.
#[derive(Debug, Clone, Serialize)]
pub struct WalletSnapshotResponse {
    pub chain_height: u64,
    pub balance: u64,
    pub available: u64,
    pub pending: u64,
    /// Pending CREDIT (incoming mempool outputs from external senders).
    /// None or omitted means zero / not computed; older clients see no field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_credit: Option<u64>,
    pub immature_count: usize,
    pub immature_value: u64,
    pub available_utxo_count: usize,
    pub total_utxo_count: usize,
    pub transactions: Vec<TransactionResponse>,
}

/// Response for `noble_getFinalityStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct FinalityStatusResponse {
    pub finalized_height: u64,
    pub finalized_hash: String,
    pub finalized_at_cycle: u64,
    pub confirmation_threshold: u32,
    pub latest_height: u64,
    pub latest_hash: String,
    pub confirmations_for_latest: u32,
    pub status: String,
}

/// Response for `noble_backupChain`.
#[derive(Debug, Clone, Serialize)]
pub struct BackupChainResponse {
    /// Absolute path to the backup file.
    pub path: String,
    /// Size of the backup file in bytes.
    pub size_bytes: u64,
}

/// Response for `noble_getEvidenceList`.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceListResponse {
    /// All stored evidence entries.
    pub evidence: Vec<EvidenceEntry>,
    /// Total number of evidence records.
    pub total: usize,
}

/// Summary of a single misbehavior evidence record.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceEntry {
    /// Hex-encoded SHA-256 hash of the CBOR evidence.
    pub evidence_hash: String,
    /// Type of misbehavior: "double_proposal" or "vote_equivocation".
    pub evidence_type: String,
    /// Hex-encoded wire bytes of the misbehaving validator.
    pub validator: String,
}

/// Response for `noble_getEvidence`.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDetailResponse {
    /// Hex-encoded SHA-256 hash of the CBOR evidence.
    pub evidence_hash: String,
    /// Type of misbehavior: "double_proposal" or "vote_equivocation".
    pub evidence_type: String,
    /// Hex-encoded wire bytes of the misbehaving validator.
    pub validator: String,
    /// Full evidence details.
    pub detail: serde_json::Value,
}

/// Response for `noble_getCheckpoints`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointsResponse {
    pub checkpoint_interval: u64,
    pub total_checkpoints: usize,
    pub highest_active_height: u64,
    pub checkpoints: Vec<CheckpointEntry>,
}

/// Single checkpoint entry.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointEntry {
    pub height: u64,
    pub hash: String,
    pub created_at_cycle: u64,
    pub activates_at_cycle: u64,
    pub active: bool,
}

/// Response for `noble_getForkResolutionStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct ForkResolutionStatusResponse {
    pub strategy: String,
    pub delay_cycles: u32,
    pub dwell_counter: u32,
    pub tracking_fork: Option<String>,
    pub finalized_floor: u64,
    pub checkpoint_floor: u64,
}

// ─── Multi-path storage sharding (Phase 5) ──────────────────────────────

/// Input row for `noble_setStoragePaths`. `target_gb = None` ⇒ Shape A
/// (auto-detect target as 90 % of free bytes at boot). `Some(0)` ⇒
/// unlimited spillover. `Some(n)` ⇒ explicit `n GiB`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoragePathInput {
    pub path: String,
    pub target_gb: Option<u64>,
}

/// One tier's runtime status, returned by `noble_getStoragePaths` and
/// echoed inside reconcile / discovery DTOs.
#[derive(Debug, Clone, Serialize)]
pub struct StoragePathInfo {
    pub path: String,
    pub target_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub sst_count: u32,
    pub other_files_bytes: u64,
    pub catalog_present: bool,
    pub catalog_updated_at: Option<u64>,
    pub is_primary: bool,
}

/// Response of `noble_getStoragePaths`. Order matches the live
/// `db_paths` list: primary first, then operator-supplied tiers.
#[derive(Debug, Clone, Serialize)]
pub struct GetStoragePathsResponse {
    pub paths: Vec<StoragePathInfo>,
    pub reconcile_mode: String,
}

/// One rejected input row from `noble_setStoragePaths`.
#[derive(Debug, Clone, Serialize)]
pub struct StoragePathRejection {
    pub path: String,
    pub reason: String,
}

/// Response of `noble_setStoragePaths`. `requires_restart` is always
/// `true` in v1 (RocksDB cannot reconfigure `db_paths` live).
#[derive(Debug, Clone, Serialize)]
pub struct SetStoragePathsResponse {
    pub accepted: Vec<String>,
    pub rejected: Vec<StoragePathRejection>,
    pub requires_restart: bool,
}

/// Single SST descriptor row in `noble_listShards` / `noble_discoverShards`.
#[derive(Debug, Clone, Serialize)]
pub struct ShardDescriptorDto {
    pub file_name: String,
    pub absolute_path: String,
    pub size_bytes: u64,
    pub content_sha256: Option<String>,
}

/// Response of `noble_listShards`. `errors` is per-file rather than
/// aborting the whole listing — one corrupt `*.sst` shouldn't hide
/// the rest of the directory.
#[derive(Debug, Clone, Serialize)]
pub struct ListShardsResponse {
    pub path: String,
    pub descriptors: Vec<ShardDescriptorDto>,
    pub errors: Vec<String>,
}

/// Per-path inventory inside `DiscoveryReportDto`.
#[derive(Debug, Clone, Serialize)]
pub struct PathInventoryDto {
    pub path: String,
    pub catalog_present: bool,
    pub catalog_chain_id: Option<u32>,
    pub catalog_updated_at: Option<u64>,
    pub discovered: Vec<ShardDescriptorDto>,
    pub missing_from_catalog: Vec<String>,
    pub extra_vs_catalog: Vec<String>,
}

/// Per-content-hash duplicate entry.
#[derive(Debug, Clone, Serialize)]
pub struct DuplicateSstDto {
    pub content_sha256: String,
    pub paths: Vec<String>,
}

/// `noble_discoverShards` response: full disk-vs-catalog picture
/// across all configured tiers.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReportDto {
    pub paths: Vec<PathInventoryDto>,
    pub duplicates: Vec<DuplicateSstDto>,
    pub strangers: Vec<ShardDescriptorDto>,
    pub hashes_available: bool,
    pub decision: String,
    pub decision_reason: Option<String>,
    /// Audit Fix #3: filesystem-level errors while walking tiers.
    /// `(path, error_message)` pairs.
    pub scan_errors: Vec<(String, String)>,
    /// Audit Fix #3: catalogs that exist but failed to parse.
    pub catalog_errors: Vec<(String, String)>,
}

/// `noble_reconcileStorage` response. Re-runs discovery and rewrites
/// every per-path catalog with the current `live_files()` view. Does
/// NOT run `DB::Repair` — that requires a restart (the running DB
/// holds a process-level lock).
#[derive(Debug, Clone, Serialize)]
pub struct ReconcileResponse {
    pub report: DiscoveryReportDto,
    pub catalogs_rewritten: u32,
    pub requires_restart: bool,
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
    fn parse_pubkey_valid_secp256k1() {
        // Generate a valid secp256k1 pubkey hex via wire format: scheme_id(0x02) + 33 bytes
        let mut wire = vec![0x02]; // secp256k1 scheme_id
        // Compressed secp256k1 key: 0x02 prefix + 32 bytes x-coordinate
        let mut key = vec![0x02]; // even-y compressed prefix
        key.extend_from_slice(&[0xAB; 32]);
        wire.extend_from_slice(&key);
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
            validator_name: None,
            transactions: vec![],
        };

        let json_str = serde_json::to_string(&br).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json_str).expect("not valid JSON");
        assert_eq!(v["height"], 42);
        assert_eq!(v["tx_count"], 3);
        assert_eq!(v["timestamp"], 1700000000u64);
        assert!(v["transactions"].as_array().unwrap().is_empty());
    }

    // --- tx_to_response: transfer_value computation ---

    /// Helper: build a minimal Transaction for testing tx_to_response.
    fn make_tx_for_response(
        tx_type: u8,
        signer_pk: &[u8],
        outputs: Vec<noble_core::TxOut>,
        inputs: Vec<noble_core::TxIn>,
    ) -> Transaction {
        Transaction {
            version: 1,
            tx_type,
            inputs,
            outputs,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: noble_crypto::SignatureEnvelope {
                scheme_id: noble_crypto::SCHEME_SECP256K1,
                public_key: signer_pk.to_vec(),
                signature: vec![0u8; 64],
            },
            additional_sigs: vec![],
            declared_cosigners: Vec::new(),
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        }
    }

    fn make_outpoint(fill: u8) -> noble_core::OutPoint {
        noble_core::OutPoint { txid: Hash256::from_bytes([fill; 32]), vout: 0 }
    }

    fn make_addr(pk_bytes: &[u8]) -> NobleAddress {
        NobleAddress::Noble(NoblePublicKey::Secp256k1(pk_bytes.to_vec()))
    }

    #[test]
    fn transfer_value_normal() {
        // Outputs to a different address → transfer_value = sum of non-signer outputs
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let (_, other_pk) = noble_crypto::secp256k1::generate_keypair();
        let signer_addr = make_addr(&signer_pk);
        let other_addr = make_addr(&other_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![
                noble_core::TxOut { value: 2000, address: other_addr },
                noble_core::TxOut { value: 500, address: signer_addr },
            ],
            vec![noble_core::TxIn { prev_output: make_outpoint(0x11) }],
        );

        let resp = tx_to_response(&tx, "deadbeef");
        assert_eq!(resp.transfer_value, 2000);
    }

    #[test]
    fn transfer_value_self_transfer() {
        // All outputs go to the signer → self-transfer fallback to total_output
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let signer_addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![
                noble_core::TxOut { value: 3000, address: signer_addr.clone() },
                noble_core::TxOut { value: 1000, address: signer_addr },
            ],
            vec![noble_core::TxIn { prev_output: make_outpoint(0x22) }],
        );

        let resp = tx_to_response(&tx, "deadbeef");
        assert_eq!(resp.transfer_value, 4000);
    }

    #[test]
    fn transfer_value_coinbase() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_COINBASE,
            &signer_pk,
            vec![noble_core::TxOut { value: 8_000_000_000, address: addr }],
            vec![noble_core::TxIn { prev_output: noble_core::OutPoint::COINBASE_PREVOUT }],
        );

        let resp = tx_to_response(&tx, "coinbase_tx_id");
        assert_eq!(resp.transfer_value, 8_000_000_000);
    }

    #[test]
    fn transfer_value_mixed_address_types() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let signer_addr = make_addr(&signer_pk);
        let (_, other_pk) = noble_crypto::secp256k1::generate_keypair();
        let other_addr = make_addr(&other_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![
                noble_core::TxOut { value: 5000, address: other_addr },
                noble_core::TxOut { value: 1000, address: signer_addr },
            ],
            vec![noble_core::TxIn { prev_output: make_outpoint(0x33) }],
        );

        let resp = tx_to_response(&tx, "mixed_tx");
        assert_eq!(resp.transfer_value, 5000);
    }

    // --- tx_to_response: input stripping ---

    #[test]
    fn inputs_stripped_for_transfer() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let (_, other_pk) = noble_crypto::secp256k1::generate_keypair();
        let other_addr = make_addr(&other_pk);

        let inputs: Vec<noble_core::TxIn> = (0..5).map(|i| noble_core::TxIn {
            prev_output: noble_core::OutPoint { txid: Hash256::from_bytes([i; 32]), vout: 0 },
        }).collect();

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![noble_core::TxOut { value: 1000, address: other_addr }],
            inputs,
        );

        let resp = tx_to_response(&tx, "transfer_tx");
        assert!(resp.inputs.is_empty(), "transfer inputs should be stripped");
        assert_eq!(resp.input_count, 5, "input_count should reflect original count");
    }

    #[test]
    fn inputs_kept_for_notarization() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_NOTARIZATION,
            &signer_pk,
            vec![noble_core::TxOut { value: 99_000, address: addr }],
            vec![noble_core::TxIn { prev_output: make_outpoint(0x44) }],
        );

        let resp = tx_to_response(&tx, "notarize_tx");
        assert_eq!(resp.inputs.len(), 1, "notarization inputs should be kept");
        assert_eq!(resp.input_count, 1);
    }

    #[test]
    fn inputs_kept_for_coinbase() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_COINBASE,
            &signer_pk,
            vec![noble_core::TxOut { value: 8_000_000_000, address: addr }],
            vec![noble_core::TxIn { prev_output: noble_core::OutPoint::COINBASE_PREVOUT }],
        );

        let resp = tx_to_response(&tx, "coinbase_tx");
        assert_eq!(resp.inputs.len(), 1, "coinbase null input should be kept");
        assert_eq!(resp.input_count, 1);
    }

    // --- tx_to_response: recipient field ---

    #[test]
    fn recipient_set_for_transfer() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let (_, other_pk) = noble_crypto::secp256k1::generate_keypair();
        let signer_addr = make_addr(&signer_pk);
        let other_addr = make_addr(&other_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![
                noble_core::TxOut { value: 2000, address: other_addr.clone() },
                noble_core::TxOut { value: 500, address: signer_addr },
            ],
            vec![noble_core::TxIn { prev_output: make_outpoint(0xA1) }],
        );

        let resp = tx_to_response(&tx, "recipient_test");
        assert!(resp.recipient.is_some(), "transfer must have recipient");
        assert_eq!(resp.recipient.unwrap(), other_addr.to_display_address());
    }

    #[test]
    fn recipient_none_for_notarization() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_NOTARIZATION,
            &signer_pk,
            vec![noble_core::TxOut { value: 99_000, address: addr }],
            vec![noble_core::TxIn { prev_output: make_outpoint(0xA2) }],
        );

        let resp = tx_to_response(&tx, "notarize_no_recipient");
        assert!(resp.recipient.is_none(), "notarization must not have recipient");
    }

    #[test]
    fn recipient_self_transfer_shows_signer() {
        let (_, signer_pk) = noble_crypto::secp256k1::generate_keypair();
        let signer_addr = make_addr(&signer_pk);

        let tx = make_tx_for_response(
            noble_core::TX_TYPE_TRANSFER,
            &signer_pk,
            vec![
                noble_core::TxOut { value: 3000, address: signer_addr.clone() },
                noble_core::TxOut { value: 1000, address: signer_addr.clone() },
            ],
            vec![noble_core::TxIn { prev_output: make_outpoint(0xA3) }],
        );

        let resp = tx_to_response(&tx, "self_transfer");
        assert!(resp.recipient.is_some(), "self-transfer must have recipient");
        assert_eq!(resp.recipient.unwrap(), signer_addr.to_display_address());
    }
}
