// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the NOBLE JSON-RPC API.
//!
//! These tests start a real jsonrpsee server, connect a WebSocket client,
//! and issue RPC calls against a MemoryStorage backend with genesis committed.

use std::sync::{Arc, Mutex, RwLock};
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
use noble_api::methods::transaction::TransactionApiServer;
use noble_api::methods::wallet::WalletApiServer;
use noble_api::{ApiState, NetworkStats};

use noble_consensus::{ConsensusConfig, CycleEngine, ValidatorList};
use noble_core::{genesis_block, MAINNET_CHAIN_ID};
use noble_mempool::Mempool;
use noble_storage::{MemoryStorage, StorageEngine};
use noble_wallet::{KeyStore, WalletState};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a fully-wired `ApiState<MemoryStorage>` with genesis committed.
fn make_test_state() -> (Arc<ApiState<MemoryStorage>>, tempfile::TempDir) {
    let storage = Arc::new(RwLock::new(MemoryStorage::new()));

    // Commit genesis block
    let genesis = genesis_block();
    let block_hash = genesis.header.compute_block_hash().expect("genesis hash");
    let tx_ids: Vec<noble_crypto::Hash256> = genesis
        .transactions
        .iter()
        .filter_map(|tx| tx.compute_tx_id(MAINNET_CHAIN_ID).ok())
        .collect();
    storage
        .read()
        .unwrap()
        .commit_block(&genesis, &block_hash, &tx_ids)
        .expect("commit genesis");

    let mempool = Arc::new(Mutex::new(Mempool::with_defaults()));
    let (network_cmd, _rx) = tokio::sync::mpsc::channel(16);
    let consensus = Arc::new(RwLock::new(CycleEngine::new(
        ConsensusConfig::default(),
        ValidatorList::new(),
        0,
        block_hash,
        MAINNET_CHAIN_ID,
        None,
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
        consensus,
        network_cmd,
        wallet_keystore,
        wallet_state,
        network_stats,
        chain_id: MAINNET_CHAIN_ID,
        start_time: Instant::now(),
        max_network_version: Arc::new(RwLock::new(noble_core::SOFTWARE_VERSION.to_string())),
        rate_limiter: None,   // disabled in tests
        totp_validator: None, // auth disabled in tests
        new_block_tx,
        new_tx_tx,
        cycle_phase_tx,
        peer_update_tx,
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
    let result: Result<serde_json::Value, _> = client
        .request("noble_lookupChecksum", rpc_params![&fake_checksum])
        .await;

    assert!(result.is_err());
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

    // Fee estimates should be positive numbers: low <= medium <= high
    let low = resp["low"].as_u64().unwrap();
    let medium = resp["medium"].as_u64().unwrap();
    let high = resp["high"].as_u64().unwrap();
    assert!(low > 0);
    assert!(low <= medium);
    assert!(medium <= high);
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
    assert_eq!(resp["size"], 0);
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

    assert_eq!(resp["version"], noble_core::PROTOCOL_VERSION as u64);
    assert_eq!(resp["chain_id"], MAINNET_CHAIN_ID);
    // uptime_secs should be a small number (just started)
    assert!(resp["uptime_secs"].as_u64().unwrap() < 60);
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
    assert_eq!(resp["chain_id"], MAINNET_CHAIN_ID);
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
// Transaction receipt methods
// ---------------------------------------------------------------------------

/// Commit a block with one transaction on top of genesis, return (block_hash, tx_id).
fn commit_block_with_tx(state: &ApiState<MemoryStorage>) -> (String, String) {
    use noble_core::{Block, BlockHeader, Transaction, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

    let (sk, pk) = ed25519::generate_keypair();
    let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());

    // Create a notarization tx
    let checksum = sha256(b"test_document");
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0,
        checksum,
        timestamp: 1_700_000_001,
        fee: 0, // zero fee so no balance needed
        recipient: None,
        amount: None,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
    };
    let msg = tx.compute_signing_message().unwrap();
    tx.publisher_sig = priv_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();

    // Get genesis hash for prev_block_hash
    let storage = state.storage.read().unwrap();
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
