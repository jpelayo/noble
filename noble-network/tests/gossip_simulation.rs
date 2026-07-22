// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Gossip simulation tests — end-to-end verification of the gossipsub pipeline.
//!
//! These tests start **real libp2p nodes** on localhost, connect them via TCP,
//! wait for gossipsub mesh formation, and verify that messages published on one
//! node are received (decoded, validated, handled) on the other.
//!
//! Unlike `three_node_integration.rs` (which injects CycleEvents directly), these
//! tests exercise the full wire path: CBOR encode → gossipsub publish → mesh
//! propagation → CBOR decode → validation → NetworkEvent emission.

mod harness;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use noble_codec::NobleCbor;
use noble_consensus::PorVote;
use noble_core::node_announce::{NodeRole, OrgType};
use noble_core::{Block, BlockHeader, NodeAnnounce, Transaction};
use noble_test_utils::fixtures::test_chain_id;
use noble_crypto::{secp256k1, Hash256, NoblePrivateKey, NoblePublicKey};
use noble_network::config::NetworkConfig;
use noble_network::messages::{NetworkCommand, NetworkEvent};
use noble_network::service::{start_network, NetworkHandle};
use noble_network::traits::{BlockProvider, TxProvider};
use noble_network::Multiaddr;

// ---------------------------------------------------------------------------
// Null providers — gossip tests don't need storage
// ---------------------------------------------------------------------------

struct NullBlockProvider;
impl BlockProvider for NullBlockProvider {
    fn get_block(&self, _: &[u8; 32]) -> Option<Block> {
        None
    }
    fn get_block_by_height(&self, _: u64) -> Option<Block> {
        None
    }
    fn get_block_header(&self, _: &[u8; 32]) -> Option<BlockHeader> {
        None
    }
    fn get_block_hash_by_height(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn chain_tip(&self) -> (u64, [u8; 32]) {
        (0, [0; 32])
    }
}

struct NullTxProvider;
impl TxProvider for NullTxProvider {
    fn get_transaction(&self, _: &[u8; 32]) -> Option<noble_core::Transaction> {
        None
    }
    fn has_transaction(&self, _: &[u8; 32]) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Network config tuned for fast gossip tests: random port, 1s heartbeat, no Kademlia.
fn gossip_test_config() -> NetworkConfig {
    NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        enable_kademlia: false,
        gossipsub_heartbeat_interval_secs: 1,
        max_outbound_per_subnet: 10,
        // Run the test nodes on the same non-zero chain the fixtures sign/key txs
        // with (`test_chain_id()`). Without this the nodes defaulted to
        // chain_id=0, so `PublishTransaction` announced `compute_tx_id(0)` while
        // the test keyed the tx provider by `compute_tx_id(test_chain_id())` — a
        // different id — so the server couldn't find the tx and the tx-relay
        // round-trip (`gossip_tx_relay_end_to_end`) timed out. Announce/vote/block
        // tests are chain-id-insensitive (their announces use chain_id=0, which
        // the cross-chain filter skips), so this is safe for them.
        chain_id: test_chain_id(),
        ..NetworkConfig::local_test()
    }
}

/// Start a lightweight gossip node (no storage, no consensus engine).
async fn start_gossip_node() -> NetworkHandle {
    let bp: Arc<dyn BlockProvider> = Arc::new(NullBlockProvider);
    let tp: Arc<dyn TxProvider> = Arc::new(NullTxProvider);
    start_network(gossip_test_config(), bp, tp)
        .await
        .expect("network should start")
}

/// Generate a validator keypair.
fn make_keypair() -> (NoblePrivateKey, NoblePublicKey) {
    let (sk, _) = secp256k1::generate_keypair();
    let priv_key = NoblePrivateKey::Secp256k1(sk);
    let pub_key = priv_key.public_key();
    (priv_key, pub_key)
}

/// Dial from `dialer` to `listener` and wait for the dial to succeed.
async fn dial_and_connect(dialer: &NetworkHandle, listener: &NetworkHandle) {
    let addr: Multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        listener.bound_port, listener.local_peer_id
    )
    .parse()
    .expect("valid multiaddr");

    let (tx, rx) = tokio::sync::oneshot::channel();
    dialer
        .command_sender()
        .send(NetworkCommand::DialPeer(addr, Some(tx)))
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("dial should complete within 5s")
        .expect("oneshot should not be dropped");
    assert!(result.is_ok(), "dial should succeed: {:?}", result.err());
}

/// Wait for gossipsub mesh to form (needs at least one heartbeat after connection).
async fn wait_for_mesh() {
    // With heartbeat_interval=1s, the first heartbeat after connection grafts the peer.
    // 2s gives margin for connection setup + heartbeat.
    tokio::time::sleep(Duration::from_secs(2)).await;
}

/// Drain events from a handle until the predicate matches, with timeout.
async fn drain_until<F: Fn(&NetworkEvent) -> bool>(
    handle: &mut NetworkHandle,
    pred: F,
    timeout_secs: u64,
) -> NetworkEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match tokio::time::timeout_at(deadline, handle.recv_event()).await {
            Ok(Some(event)) => {
                if pred(&event) {
                    return event;
                }
                // Skip non-matching events (PeerConnected, SyncComplete, etc.)
            }
            Ok(None) => panic!("event channel closed unexpectedly"),
            Err(_) => panic!("timed out after {timeout_secs}s waiting for expected event"),
        }
    }
}

/// Create and sign a NodeAnnounce with optional chain_tip fields.
fn make_signed_announce(
    sk: &NoblePrivateKey,
    pk: &NoblePublicKey,
    chain_tip_height: Option<u64>,
    chain_tip_hash: Option<[u8; 32]>,
    proposed_height: Option<u64>,
    proposed_hash: Option<[u8; 32]>,
) -> NodeAnnounce {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    NodeAnnounce::sign_with_attestation(
        pk.clone(),
        "gossip-sim-node".to_string(),
        OrgType::Individual,
        None,
        NodeRole::FullNode,
        None,
        None,
        None,
        None,
        false,
        false,
        chain_tip_height,
        chain_tip_hash,
        proposed_height,
        proposed_hash,
        0,
        String::new(),
        None, // chain_vote_weight
        None, // min_fee_rate
        now,
        sk,
        None,
    )
    .expect("signing should succeed")
}

/// Shutdown helper — send shutdown command.
async fn shutdown(handle: &NetworkHandle) {
    let _ = handle
        .command_sender()
        .send(NetworkCommand::Shutdown)
        .await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// NodeAnnounce published on A is received on B with correct fields and valid signature.
#[tokio::test]
async fn gossip_node_announce_end_to_end() {
    let node_a = start_gossip_node().await;
    let mut node_b = start_gossip_node().await;

    dial_and_connect(&node_a, &node_b).await;
    wait_for_mesh().await;

    // Create and publish a signed NodeAnnounce.
    let (sk, pk) = make_keypair();
    let announce = make_signed_announce(&sk, &pk, None, None, None, None);
    node_a
        .command_sender()
        .send(NetworkCommand::PublishNodeAnnounce(Box::new(
            announce.clone(),
        )))
        .await
        .unwrap();

    // Node B should receive NodeAnnounceReceived.
    let event = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::NodeAnnounceReceived { .. }),
        10,
    )
    .await;

    if let NetworkEvent::NodeAnnounceReceived { announce: recv, .. } = event {
        assert_eq!(recv.node_name, "gossip-sim-node");
        assert_eq!(recv.identity_key, pk);
        assert_eq!(recv.org_type, OrgType::Individual);
        assert_eq!(recv.node_role, NodeRole::FullNode);
        assert!(recv.verify_signature().is_ok(), "signature must be valid");
    } else {
        panic!("expected NodeAnnounceReceived");
    }

    shutdown(&node_a).await;
    shutdown(&node_b).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// NodeAnnounce with chain_tip_height triggers PeerChainTipUpdated on the receiver.
#[tokio::test]
async fn gossip_node_announce_chain_tip_emits_peer_update() {
    let node_a = start_gossip_node().await;
    let mut node_b = start_gossip_node().await;

    dial_and_connect(&node_a, &node_b).await;
    wait_for_mesh().await;

    // Create announce with chain_tip_height=42.
    let (sk, pk) = make_keypair();
    let tip_hash = [0xBB_u8; 32];
    let announce = make_signed_announce(&sk, &pk, Some(42), Some(tip_hash), None, None);
    node_a
        .command_sender()
        .send(NetworkCommand::PublishNodeAnnounce(Box::new(announce)))
        .await
        .unwrap();

    // Node B should receive PeerChainTipUpdated with the announced height.
    let event = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::PeerChainTipUpdated { .. }),
        10,
    )
    .await;

    if let NetworkEvent::PeerChainTipUpdated {
        height, tip_hash: h, ..
    } = event
    {
        assert_eq!(height, 42);
        assert_eq!(h, tip_hash);
    } else {
        panic!("expected PeerChainTipUpdated");
    }

    // Also verify NodeAnnounceReceived arrives with chain_tip fields populated.
    let event2 = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::NodeAnnounceReceived { .. }),
        5,
    )
    .await;
    if let NetworkEvent::NodeAnnounceReceived { announce: recv, .. } = event2 {
        assert_eq!(recv.chain_tip_height, Some(42));
        assert_eq!(recv.chain_tip_hash, Some(tip_hash));
    } else {
        panic!("expected NodeAnnounceReceived");
    }

    shutdown(&node_a).await;
    shutdown(&node_b).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Block published on A arrives as BlockAnnounced on B with correct hash and height.
#[tokio::test]
async fn gossip_block_announce_end_to_end() {
    let node_a = start_gossip_node().await;
    let mut node_b = start_gossip_node().await;

    dial_and_connect(&node_a, &node_b).await;
    wait_for_mesh().await;

    // Create a properly signed block.
    let (sk, pk) = make_keypair();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    struct NoopLookup;
    impl noble_consensus::proposal::UtxoValueLookup for NoopLookup {
        fn utxo_value(&self, _: &noble_core::OutPoint) -> Option<u64> { None }
    }
    let block = noble_consensus::propose_block(
        &[],
        Hash256::ZERO,
        1,
        now,
        test_chain_id(),
        &sk,
        &pk,
        8 * 1024 * 1024,
        &NoopLookup,
        None,
    )
    .expect("block proposal should succeed");
    let expected_hash = block.header.compute_block_hash().unwrap();

    node_a
        .command_sender()
        .send(NetworkCommand::PublishBlock(block))
        .await
        .unwrap();

    // Node B should receive BlockAnnounced.
    let event = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::BlockAnnounced { .. }),
        10,
    )
    .await;

    if let NetworkEvent::BlockAnnounced { hash, height, .. } = event {
        assert_eq!(Hash256(hash), expected_hash);
        assert_eq!(height, 1);
    } else {
        panic!("expected BlockAnnounced");
    }

    shutdown(&node_a).await;
    shutdown(&node_b).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Vote published on A arrives as VoteReceived on B with correct fields and valid signature.
#[tokio::test]
async fn gossip_vote_end_to_end() {
    let node_a = start_gossip_node().await;
    let mut node_b = start_gossip_node().await;

    dial_and_connect(&node_a, &node_b).await;
    wait_for_mesh().await;

    // Create a signed vote.
    let (sk, pk) = make_keypair();
    let candidate = Hash256([0xFF; 32]);
    let vote = PorVote::sign(7, candidate, &sk, pk.clone()).unwrap();

    // Convert to wire format for PublishVote.
    let voter_id = vote.voter_pubkey.to_wire_bytes();
    let signature = vote.signature.to_cbor().unwrap();
    let candidate_hash = *vote.candidate_hash.as_bytes();

    node_a
        .command_sender()
        .send(NetworkCommand::PublishVote {
            cycle: 7,
            candidate_hash,
            voter_id: voter_id.clone(),
            signature: signature.clone(),
            round: 1,
        })
        .await
        .unwrap();

    // Node B should receive VoteReceived.
    let event = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::VoteReceived { .. }),
        10,
    )
    .await;

    if let NetworkEvent::VoteReceived {
        cycle,
        candidate_hash: recv_hash,
        voter_id: recv_voter,
        signature: recv_sig,
        round,
        ..
    } = event
    {
        assert_eq!(cycle, 7);
        assert_eq!(recv_hash, candidate_hash);
        assert_eq!(round, 1);

        // Reconstruct the vote and verify the signature survived the wire trip.
        let recovered =
            harness::wire_to_por_vote_public(7, &recv_hash, &recv_voter, &recv_sig, 1);
        assert!(recovered.is_some(), "vote should reconstruct from wire");
        assert!(
            recovered.unwrap().verify().is_ok(),
            "recovered vote signature must be valid"
        );
    } else {
        panic!("expected VoteReceived");
    }

    shutdown(&node_a).await;
    shutdown(&node_b).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// ---------------------------------------------------------------------------
// Transaction relay test
// ---------------------------------------------------------------------------

/// In-memory TxProvider that can hold pending transactions (simulates mempool).
struct MemoryTxProvider {
    txs: parking_lot::Mutex<HashMap<[u8; 32], Transaction>>,
}

impl MemoryTxProvider {
    fn new() -> Self {
        Self {
            txs: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, tx_id: [u8; 32], tx: Transaction) {
        self.txs.lock().insert(tx_id, tx);
    }
}

impl TxProvider for MemoryTxProvider {
    fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<Transaction> {
        self.txs.lock().get(tx_id).cloned()
    }
    fn has_transaction(&self, tx_id: &[u8; 32]) -> bool {
        self.txs.lock().contains_key(tx_id)
    }
}

/// Start a gossip node that uses a MemoryTxProvider (can serve pending txs).
async fn start_gossip_node_with_tx_provider(
    tx_provider: Arc<dyn TxProvider>,
) -> NetworkHandle {
    let bp: Arc<dyn BlockProvider> = Arc::new(NullBlockProvider);
    start_network(gossip_test_config(), bp, tx_provider)
        .await
        .expect("network should start")
}

/// Transaction published on A arrives as TransactionReceived on B via the full
/// TxAnnounce → TxRequest → TxResponse pipeline.
#[tokio::test]
async fn gossip_tx_relay_end_to_end() {
    use noble_core::{OutPoint, TxIn, TxOut, NobleAddress, PROTOCOL_VERSION};
    use noble_crypto::{NobleSigner, SignatureEnvelope};

    // Node A: has a MemoryTxProvider so it can serve the tx when B requests it.
    let tx_provider_a = Arc::new(MemoryTxProvider::new());
    let node_a = start_gossip_node_with_tx_provider(tx_provider_a.clone() as Arc<dyn TxProvider>).await;

    // Node B: NullTxProvider (B is the receiver, not the server).
    let mut node_b = start_gossip_node().await;

    dial_and_connect(&node_a, &node_b).await;
    wait_for_mesh().await;

    // Build a minimal signed test transaction.
    let (sk, pk) = make_keypair();
    let addr = NobleAddress::Noble(pk.clone());
    let checksum = noble_crypto::sha256(b"test-doc-for-tx-relay");
    let prev_outpoint = OutPoint {
        txid: noble_crypto::sha256(&pk.key_bytes()),
        vout: 0,
    };
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0,
        inputs: vec![TxIn { prev_output: prev_outpoint }],
        outputs: vec![TxOut { value: 100_000_000, address: addr }],
        checksum,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        issuer_sig: SignatureEnvelope {
            scheme_id: pk.scheme_id(),
            public_key: pk.key_bytes().to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
        expires_at: None,
    };
    let msg = tx
        .compute_signing_message_for_chain(test_chain_id())
        .unwrap();
    tx.issuer_sig = sk.sign(&msg).unwrap();

    // Compute tx_id and insert into Node A's provider.
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
    tx_provider_a.insert(*tx_id.as_bytes(), tx.clone());

    // Publish the transaction on Node A.
    node_a
        .command_sender()
        .send(NetworkCommand::PublishTransaction(tx))
        .await
        .unwrap();

    // Node B should receive TransactionReceived (full tx body via TxRequest/TxResponse).
    let event = drain_until(
        &mut node_b,
        |e| matches!(e, NetworkEvent::TransactionReceived { .. }),
        10,
    )
    .await;

    if let NetworkEvent::TransactionReceived { transaction, .. } = event {
        let received_id = transaction.compute_tx_id(test_chain_id()).unwrap();
        assert_eq!(received_id, tx_id, "relayed tx_id must match original");
    } else {
        panic!("expected TransactionReceived");
    }

    shutdown(&node_a).await;
    shutdown(&node_b).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
}
