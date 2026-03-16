// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the NOBLE JSON-RPC API.
//!
//! These tests start a real jsonrpsee server, connect a WebSocket client,
//! and issue RPC calls against a MemoryStorage backend with genesis committed.

use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use std::time::Instant;

use jsonrpsee::core::client::ClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::server::Server;
use jsonrpsee::ws_client::WsClientBuilder;
use jsonrpsee::RpcModule;

use noble_api::methods::address::AddressApiServer;
use noble_api::methods::block::BlockApiServer;
use noble_api::methods::consensus::ConsensusApiServer;
use noble_api::methods::document::DocumentApiServer;
use noble_api::methods::mempool::MempoolApiServer;
use noble_api::methods::network::NetworkApiServer;
use noble_api::methods::node::NodeApiServer;
use noble_api::methods::storage::StorageApiServer;
use noble_api::methods::transaction::TransactionApiServer;
use noble_api::methods::wallet::WalletApiServer;
use noble_api::{ApiState, NetworkStats, NodeIdentityData};

use noble_consensus::{ConsensusConfig, CycleEngine};
use noble_mempool::Mempool;
use noble_test_utils::fixtures::{test_chain_id, test_genesis_block, test_genesis_hash};
use noble_storage::{MemoryStorage, StorageEngine};
use noble_wallet::{KeyStore, WalletState};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a fully-wired `ApiState<MemoryStorage>` with genesis committed.
fn make_test_state() -> (Arc<ApiState<MemoryStorage>>, tempfile::TempDir) {
    let storage = Arc::new(RwLock::new(MemoryStorage::new()));

    // Commit genesis block
    let genesis = test_genesis_block();
    let block_hash = genesis.header.compute_block_hash().expect("genesis hash");
    let tx_ids: Vec<noble_crypto::Hash256> = genesis
        .transactions
        .iter()
        .filter_map(|tx| tx.compute_tx_id(test_chain_id()).ok())
        .collect();
    storage
        .read()
        .commit_block(&genesis, &block_hash, &tx_ids)
        .expect("commit genesis");

    let mempool = Arc::new(Mutex::new(Mempool::with_defaults()));
    let (network_cmd, _rx) = tokio::sync::mpsc::channel(16);
    let consensus = Arc::new(RwLock::new(CycleEngine::new(
        ConsensusConfig::default(),
        0,
        block_hash,
        test_chain_id(),
        None,
        Some(noble_core::GENESIS_TIMESTAMP),
    )));

    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = KeyStore::new(dir.path()).expect("keystore");
    let wallet_keystore = Arc::new(Mutex::new(keystore));
    let wallet_state = Arc::new(Mutex::new(WalletState::new(3600)));
    let network_stats = Arc::new(RwLock::new(NetworkStats::default()));

    let (new_block_tx, _) = tokio::sync::broadcast::channel(16);
    let (new_tx_tx, _) = tokio::sync::broadcast::channel(16);
    let (cycle_phase_tx, _) = tokio::sync::broadcast::channel(16);
    let (peer_update_tx, _) = tokio::sync::broadcast::channel(16);

    let state = Arc::new(ApiState {
        storage,
        mempool,
        validator_registry: Arc::new(RwLock::new(noble_consensus::ValidatorRegistry::new(
            noble_consensus::ValidatorList::new(),
            None,
        ))),
        consensus,
        network_cmd,
        wallet_keystore,
        wallet_state,
        network_stats,
        chain_id: Arc::new(std::sync::atomic::AtomicU32::new(test_chain_id())),
        start_time: Instant::now(),
        max_network_version: Arc::new(RwLock::new(noble_core::SOFTWARE_VERSION.to_string())),
        rate_limiter: None,   // disabled in tests
        totp_validator: None, // auth disabled in tests
        totp_scope: noble_api::middleware::TotpScope::All,
        totp_secret_path: None,
        rpc_port: 8783,
        ws_port: 8784,
        p2p_port: 8780,
        new_block_tx,
        new_tx_tx,
        cycle_phase_tx,
        peer_update_tx,
        trace_handle: None,             // trace disabled in tests
        gateway_key: RwLock::new(None), // no gateway in tests
        gateway_key_path: None,
        ip_filter: None, // no IP filter in tests
        validator_list_path: None,
        peer_info: Arc::new(RwLock::new(std::collections::HashMap::new())),
        node_identity: Arc::new(RwLock::new(NodeIdentityData {
            node_name: String::new(),
            org_type: "Individual".to_string(),
            org_name: String::new(),
            node_role: "FullNode".to_string(),
            contact_email: String::new(),
            website: String::new(),
            host_address: String::new(),
            country_code: String::new(),
            wants_to_validate: false,
            wants_to_vote: false,
            p2p_port: 8780,
            setup_complete: false,
        })),
        identity_path: None,
        tls_fingerprint: parking_lot::RwLock::new(None),
        tls_expires_at: parking_lot::RwLock::new(None),
        tls_expiry_secs: parking_lot::RwLock::new(None),
        tls_sans: parking_lot::RwLock::new(vec![]),
        tls_regenerate: None,
        tls_upload: None,
        setup_mode: false,
        allowed_cors_origins: std::sync::Arc::new(parking_lot::RwLock::new(vec![
            "http://127.0.0.1:8785".into(),
            "http://localhost:8785".into(),
        ])),
        rpc_origins: std::sync::Arc::new(parking_lot::RwLock::new(vec![
            "http://127.0.0.1:8783".into(),
            "ws://127.0.0.1:8784".into(),
        ])),
        cors_scheme: "http".to_string(),
        gui_port: 8785,
        tls_plaintext_mode: false,
        peer_id: "12D3KooWTestPeerIdPlaceholder".to_string(),
        validator_pubkey: None,
        validator_scheme: None,
        validator_key_path: None,
        data_dir: None,
        pruning_mode: "archive".to_string(),
        keep_blocks: 0,
        reward_address: parking_lot::RwLock::new(None),
        enable_totp: None,
        set_config_value: None,
        config_path: None,
        chain_meta: [0x42u8; 32],
        seeds: parking_lot::RwLock::new(Vec::new()),
        announce_trigger: tokio::sync::mpsc::channel(4).0,
        cache_size_mb: 64,
        compression_enabled: true,
        max_db_size_gb: 0,
        network_name: format!("{:08X}", test_chain_id()),
        genesis_hash: hex::encode(test_genesis_hash().as_bytes()),
        discovered_blockchains: std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        fork_resolver: std::sync::Arc::new(parking_lot::Mutex::new(
            noble_consensus::ForkResolver::new(
                noble_consensus::ForkResolutionStrategy::LongestMostLegitimate,
                3,
            ),
        )),
        max_peers: std::sync::atomic::AtomicU32::new(50),
        sync_behind: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        sync_target_height: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sync_progress_current: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sync_progress_total: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    });

    (state, dir)
}

/// Start a jsonrpsee server with all RPC modules merged, return (ws_url, handle).
async fn start_test_server(
    state: Arc<ApiState<MemoryStorage>>,
) -> (String, jsonrpsee::server::ServerHandle) {
    let server = Server::builder()
        .build("127.0.0.1:0")
        .await
        .expect("bind server");
    let addr = server.local_addr().expect("local addr");

    let mut module = RpcModule::new(());
    module
        .merge(BlockApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(DocumentApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(TransactionApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(MempoolApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(NetworkApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(ConsensusApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(AddressApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(WalletApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(NodeApiServer::into_rpc(state.clone()))
        .unwrap();
    module
        .merge(StorageApiServer::into_rpc(state.clone()))
        .unwrap();

    let handle = server.start(module);
    (format!("ws://{addr}"), handle)
}

// ---------------------------------------------------------------------------
// Block methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_block_count_genesis() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getBlockCount", rpc_params![])
        .await
        .unwrap();

    assert_eq!(resp["height"], 0);
    // Block hash should be a 64-char hex string
    let hash_str = resp["block_hash"].as_str().unwrap();
    assert_eq!(hash_str.len(), 64);
}

#[tokio::test]
async fn get_latest_block_returns_genesis() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getLatestBlock", rpc_params![])
        .await
        .unwrap();

    assert_eq!(resp["height"], 0);
    assert_eq!(resp["tx_count"], 0);
    // prev_hash of genesis is all zeros
    let prev_hash = resp["prev_hash"].as_str().unwrap();
    assert_eq!(prev_hash, "0".repeat(64));
}

#[tokio::test]
async fn get_block_by_height() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getBlock", rpc_params![0u64])
        .await
        .unwrap();

    assert_eq!(resp["height"], 0);
    assert_eq!(resp["tx_count"], 0);
}

#[tokio::test]
async fn get_block_by_hash() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state.clone()).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // First get the genesis hash via getBlockCount
    let count: serde_json::Value = client
        .request("noble_getBlockCount", rpc_params![])
        .await
        .unwrap();
    let genesis_hash = count["block_hash"].as_str().unwrap().to_string();

    // Now look up by hash
    let resp: serde_json::Value = client
        .request("noble_getBlock", rpc_params![&genesis_hash])
        .await
        .unwrap();

    assert_eq!(resp["height"], 0);
    assert_eq!(resp["hash"].as_str().unwrap(), genesis_hash);
}

#[tokio::test]
async fn get_block_not_found() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // Height 999 does not exist
    let result: Result<serde_json::Value, _> =
        client.request("noble_getBlock", rpc_params![999u64]).await;

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Document methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lookup_checksum_not_found() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // A random checksum that was never registered
    let fake_checksum = "aa".repeat(32);
    let result: serde_json::Value = client
        .request("noble_lookupChecksum", rpc_params![&fake_checksum])
        .await
        .expect("lookupChecksum should return a response, not an error");

    assert_eq!(
        result["found"], false,
        "unknown checksum should return found: false"
    );
    assert!(
        result["records"].as_array().unwrap().is_empty(),
        "records should be empty"
    );
}

// ---------------------------------------------------------------------------
// Transaction methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_transaction_not_found() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let fake_tx_id = "ff".repeat(32);
    let result: Result<serde_json::Value, _> = client
        .request("noble_getTransaction", rpc_params![&fake_tx_id])
        .await;

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Mempool methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn estimate_fee() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_estimateFee", rpc_params![])
        .await
        .unwrap();

    // Fee estimates should be positive numbers: min_fee <= recommended_fee <= high_priority_fee
    let min_fee = resp["min_fee"].as_u64().unwrap();
    let recommended = resp["recommended_fee"].as_u64().unwrap();
    let high_priority = resp["high_priority_fee"].as_u64().unwrap();
    assert!(min_fee > 0);
    assert!(min_fee <= recommended);
    assert!(recommended <= high_priority);
}

#[tokio::test]
async fn get_mempool_info() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getMempoolInfo", rpc_params![])
        .await
        .unwrap();

    // Empty mempool
    assert_eq!(resp["count"], 0);
    assert_eq!(resp["total_bytes"], 0);
}

// ---------------------------------------------------------------------------
// Address methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_address_valid() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // A valid Ed25519 wire-format address: scheme_id=0x01 + 32 bytes
    let mut wire = vec![0x01u8]; // SCHEME_ED25519
    wire.extend_from_slice(&[0xaa; 32]);
    let address_hex = hex::encode(&wire);

    let resp: serde_json::Value = client
        .request("noble_validateAddress", rpc_params![&address_hex])
        .await
        .unwrap();

    assert_eq!(resp["valid"], true);
    assert_eq!(resp["scheme_id"], 1); // SCHEME_ED25519
}

#[tokio::test]
async fn validate_address_invalid() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // Invalid: not valid hex
    let resp: serde_json::Value = client
        .request("noble_validateAddress", rpc_params!["not-hex-at-all"])
        .await
        .unwrap();
    assert_eq!(resp["valid"], false);

    // Invalid: wrong length (too short for any scheme)
    let resp2: serde_json::Value = client
        .request("noble_validateAddress", rpc_params!["0102"])
        .await
        .unwrap();
    assert_eq!(resp2["valid"], false);
}

// ---------------------------------------------------------------------------
// Node methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_node_info() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getNodeInfo", rpc_params![])
        .await
        .unwrap();

    assert_eq!(resp["version"], noble_core::SOFTWARE_VERSION);
    assert_eq!(
        resp["protocol_version"],
        noble_core::PROTOCOL_VERSION as u64
    );
    // Chain identity always available (genesis committed at startup).
    assert_eq!(resp["chain_id"], test_chain_id());
    // uptime_secs should be a small number (just started)
    assert!(resp["uptime_secs"].as_u64().unwrap() < 60);
    assert_eq!(resp["rpc_port"], 8783);
    assert_eq!(resp["ws_port"], 8784);
    assert_eq!(resp["p2p_port"], 8780);
}

// ---------------------------------------------------------------------------
// Chain stats
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_chain_stats() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getChainStats", rpc_params![])
        .await
        .unwrap();

    assert_eq!(resp["height"], 0);
    // Chain identity always available (genesis committed at startup).
    assert_eq!(resp["chain_id"], test_chain_id());
}

// ---------------------------------------------------------------------------
// Network methods
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_network_info() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getNetworkInfo", rpc_params![])
        .await
        .unwrap();

    // Default NetworkStats are all zeros
    assert_eq!(resp["peer_count"], 0);
    assert_eq!(resp["inbound"], 0);
    assert_eq!(resp["outbound"], 0);
}

// ---------------------------------------------------------------------------
// Sync status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_sync_status_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getSyncStatus", rpc_params![])
        .await
        .unwrap();

    assert_eq!(resp["synced"], true);
    assert_eq!(resp["current_height"], 0);
    assert!(resp["highest_known"].is_number());
    assert!(resp["progress"].is_number());
    assert!(resp["state"].is_string());
}

// ---------------------------------------------------------------------------
// Cycle status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_cycle_status_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getCycleStatus", rpc_params![])
        .await
        .unwrap();

    // cycle_number is null when bootstrapping (no genesis), number otherwise.
    assert!(resp["cycle_number"].is_number() || resp["cycle_number"].is_null());
    assert!(resp["phase"].is_string());
    assert!(resp["phase_index"].is_number());
    assert!(resp["phase_remaining_secs"].is_number());
    assert!(resp["cycle_remaining_secs"].is_number());
}

// ---------------------------------------------------------------------------
// Address balance shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_address_balance_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // Create a valid ed25519 address
    let mut wire = vec![0x01u8]; // Ed25519 scheme_id
    wire.extend_from_slice(&[0xAB; 32]);
    let addr = hex::encode(&wire);

    let resp: serde_json::Value = client
        .request("noble_getAddressBalance", rpc_params![&addr])
        .await
        .unwrap();

    assert_eq!(resp["public_key"], addr);
    assert!(resp["balance"].is_number());
    assert!(resp["available"].is_number());
    assert!(resp["pending"].is_number());
    assert!(resp["tx_count"].is_number());
}

// ---------------------------------------------------------------------------
// Address history shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_address_history_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let mut wire = vec![0x01u8];
    wire.extend_from_slice(&[0xAB; 32]);
    let addr = hex::encode(&wire);

    let resp: serde_json::Value = client
        .request("noble_getAddressHistory", rpc_params![&addr, 0, 10])
        .await
        .unwrap();

    assert_eq!(resp["public_key"], addr);
    assert!(resp["transactions"].is_array());
    assert!(resp["total"].is_number());
    assert_eq!(resp["page"], 0);
    assert_eq!(resp["limit"], 10);
}

// ---------------------------------------------------------------------------
// Wallet info shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_wallet_info_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getWalletInfo", rpc_params![])
        .await
        .unwrap();

    assert!(!resp["unlocked"].as_bool().unwrap());
    assert!(resp["key_count"].is_number());
    assert!(resp["balance"].is_number());
    assert!(resp["available"].is_number());
    assert!(resp["pending"].is_number());
}

// ---------------------------------------------------------------------------
// Validator list shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_validator_list_shape() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getValidatorList", rpc_params![])
        .await
        .unwrap();

    assert!(resp["selection_policy"].is_string());
    assert!(resp["validators"].is_array());
    assert!(resp["count"].is_number());
}

// ---------------------------------------------------------------------------
// Transaction receipt methods
// ---------------------------------------------------------------------------

/// Commit a block with one coinbase transaction on top of genesis, return (block_hash, tx_id).
fn commit_block_with_tx(state: &ApiState<MemoryStorage>) -> (String, String) {
    use noble_core::{
        Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut, PROTOCOL_VERSION,
        TX_TYPE_COINBASE,
    };
    use noble_crypto::{
        ed25519, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    let (sk, pk) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
    let addr = noble_core::NobleAddress::Noble(NoblePublicKey::Ed25519(pk.to_vec()));

    // Create a coinbase tx (valid — no UTXO inputs to verify)
    let subsidy = noble_core::subsidy_at_height(1);
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_COINBASE,
        inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
        outputs: vec![TxOut { value: subsidy, address: addr }],
        checksum: noble_crypto::Hash256::ZERO,
        timestamp: 1_700_000_001,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
            contract_data: None,
    };
    let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx.publisher_sig = priv_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

    // Get genesis hash for prev_block_hash
    let storage = state.storage.read();
    let tip = storage.get_chain_tip().unwrap().unwrap();
    let prev_hash = tip.block_hash;

    let val_pub = NoblePublicKey::Ed25519(pk.to_vec());
    let tx_ids = vec![tx_id];
    let merkle_root = noble_core::compute_merkle_root(&tx_ids);

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1_700_000_001,
        height: 1,
        tx_count: 1,
        validator_id: val_pub,
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
    };
    let hmsg = header.compute_signing_message().unwrap();
    header.validator_sig = priv_key.sign(&hmsg).unwrap();
    let block_hash = header.compute_block_hash().unwrap();

    let block = Block {
        header,
        transactions: vec![tx],
    };
    storage.commit_block(&block, &block_hash, &tx_ids).unwrap();

    (
        noble_api::types::hash_to_hex(&block_hash),
        noble_api::types::hash_to_hex(&tx_id),
    )
}

#[tokio::test]
async fn get_transaction_receipt_confirmed() {
    let (state, _dir) = make_test_state();
    let (block_hash, tx_id) = commit_block_with_tx(&state);
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getTransactionReceipt", rpc_params![&tx_id])
        .await
        .unwrap();

    assert_eq!(resp["status"], "confirmed");
    assert_eq!(resp["block_height"], 1);
    assert_eq!(resp["block_hash"].as_str().unwrap(), block_hash);
    assert_eq!(resp["tx_index"], 0);
    assert_eq!(resp["confirmations"], 1);
    assert_eq!(resp["transaction"]["tx_id"].as_str().unwrap(), tx_id);
}

#[tokio::test]
async fn get_transaction_receipt_not_found() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let fake_tx_id = "ff".repeat(32);
    let result: Result<serde_json::Value, _> = client
        .request("noble_getTransactionReceipt", rpc_params![&fake_tx_id])
        .await;

    assert!(result.is_err());
}

// --- Finding 5: Multi-address integration tests ---

#[tokio::test]
async fn validate_address_bitcoin_p2wpkh() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // BIP-173 test vector
    let result: serde_json::Value = client
        .request(
            "noble_validateAddress",
            rpc_params!["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],
        )
        .await
        .unwrap();

    assert_eq!(result["valid"], true);
    assert_eq!(result["address_type"], "bitcoin_hash160");
}

#[tokio::test]
async fn validate_address_bitcoin_testnet_rejected() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    // tb1q... should be invalid (Bitcoin testnet addresses not supported)
    let result: serde_json::Value = client
        .request(
            "noble_validateAddress",
            rpc_params!["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"],
        )
        .await
        .unwrap();

    assert_eq!(result["valid"], false);
}

#[tokio::test]
async fn get_storage_stats_returns_valid_response() {
    let (state, _dir) = make_test_state();
    let (url, _handle) = start_test_server(state).await;
    let client = WsClientBuilder::default().build(&url).await.unwrap();

    let resp: serde_json::Value = client
        .request("noble_getStorageStats", rpc_params![])
        .await
        .unwrap();

    // MemoryStorage returns empty CF list (default trait impl)
    assert!(resp["column_families"].is_array());
    assert_eq!(resp["total_db_bytes"], 0);
    assert_eq!(resp["cache_size_bytes"], 64 * 1024 * 1024);
    assert_eq!(resp["compression_enabled"], true);
}
