// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Integration test harness: glue functions for wiring consensus CycleIo/CycleEvent
//! with network NetworkCommand/NetworkEvent.

pub mod node;

use noble_codec::NobleCbor;
use noble_consensus::{CycleEvent, CycleIo, PorVote};
use noble_crypto::{Hash256, NoblePublicKey};
use noble_network::messages::{NetworkCommand, NetworkEvent};

/// Convert a consensus `CycleIo` action into zero or more `NetworkCommand`s.
pub fn cycle_io_to_network_commands(io: CycleIo) -> Vec<NetworkCommand> {
    match io {
        CycleIo::BroadcastBlock(block) => {
            vec![NetworkCommand::PublishBlock(*block)]
        }
        CycleIo::BroadcastVote(vote) => {
            vec![NetworkCommand::PublishVote {
                cycle: vote.cycle,
                candidate_hash: *vote.candidate_hash.as_bytes(),
                voter_id: vote.voter_pubkey.to_wire_bytes(),
                signature: vote_to_signature_bytes(&vote),
            }]
        }
        CycleIo::BanPeer { peer_id, .. } => {
            vec![NetworkCommand::BanPeer(peer_id)]
        }
        CycleIo::RequestBlock {
            peer_id,
            block_hash,
        } => {
            vec![NetworkCommand::RequestBlock {
                peer_id,
                hash: *block_hash.as_bytes(),
            }]
        }
        // CommitBlock, ReadmitTransactions, SetTimer, EmitMetric, Log
        // are handled locally by the node, not sent to the network.
        _ => vec![],
    }
}

/// Convert a `NetworkEvent` into a consensus `CycleEvent` (if applicable).
///
/// Returns `None` for events that don't map to consensus inputs (e.g., PeerConnected).
#[allow(dead_code)]
pub fn network_event_to_cycle_event(event: &NetworkEvent) -> Option<CycleEvent> {
    match event {
        NetworkEvent::BlockReceived { peer_id, block } => Some(CycleEvent::BlockProposed {
            block: Box::new(block.clone()),
            from_peer: peer_id.clone(),
        }),
        NetworkEvent::VoteReceived {
            cycle,
            candidate_hash,
            voter_id,
            signature,
        } => {
            // Reconstruct PorVote from wire bytes.
            let vote = wire_to_por_vote(*cycle, candidate_hash, voter_id, signature)?;
            Some(CycleEvent::VoteReceived {
                vote,
                from_peer: voter_id.clone(),
            })
        }
        _ => None,
    }
}

/// Serialize a `PorVote`'s signature into wire bytes for network transmission.
fn vote_to_signature_bytes(vote: &PorVote) -> Vec<u8> {
    // Encode the full SignatureEnvelope as CBOR for wire transport.
    vote.signature.to_cbor().unwrap_or_default()
}

/// Reconstruct a `PorVote` from wire bytes received over the network.
///
/// Public for use in integration tests.
pub fn wire_to_por_vote_public(
    cycle: u64,
    candidate_hash: &[u8; 32],
    voter_id: &[u8],
    signature_bytes: &[u8],
) -> Option<PorVote> {
    wire_to_por_vote(cycle, candidate_hash, voter_id, signature_bytes)
}

fn wire_to_por_vote(
    cycle: u64,
    candidate_hash: &[u8; 32],
    voter_id: &[u8],
    signature_bytes: &[u8],
) -> Option<PorVote> {
    let voter_pubkey = NoblePublicKey::from_wire_bytes(voter_id).ok()?;
    let candidate_hash = Hash256(*candidate_hash);
    let signature: noble_crypto::SignatureEnvelope =
        noble_crypto::SignatureEnvelope::from_cbor(signature_bytes).ok()?;

    Some(PorVote {
        cycle,
        candidate_hash,
        voter_pubkey,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_consensus::PorVote;
    use noble_core::{Block, BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{ed25519, Hash256, NoblePrivateKey, SignatureEnvelope};

    #[test]
    fn broadcast_block_converts_to_publish_command() {
        let block = Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000,
                height: 1,
                tx_count: 0,
                validator_id: NoblePublicKey::Ed25519(vec![0; 32]),
                validator_sig: SignatureEnvelope {
                    scheme_id: 0,
                    public_key: vec![],
                    signature: vec![],
                },
            },
            transactions: vec![],
        };
        let cmds = cycle_io_to_network_commands(CycleIo::BroadcastBlock(Box::new(block)));
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], NetworkCommand::PublishBlock(_)));
    }

    #[test]
    fn broadcast_vote_converts_to_publish_vote_command() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let vote = PorVote::sign(1, Hash256::ZERO, &priv_key, pub_key).unwrap();
        let cmds = cycle_io_to_network_commands(CycleIo::BroadcastVote(vote));
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], NetworkCommand::PublishVote { .. }));
    }

    #[test]
    fn vote_roundtrip_wire_conversion() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let original = PorVote::sign(5, Hash256([0xAA; 32]), &priv_key, pub_key).unwrap();

        // Convert to wire format.
        let wire_voter_id = original.voter_pubkey.to_wire_bytes();
        let wire_sig = vote_to_signature_bytes(&original);
        let wire_hash = *original.candidate_hash.as_bytes();

        // Convert back.
        let recovered = wire_to_por_vote(5, &wire_hash, &wire_voter_id, &wire_sig).unwrap();
        assert_eq!(recovered.cycle, 5);
        assert_eq!(recovered.candidate_hash, original.candidate_hash);
        // Verify the recovered vote.
        assert!(recovered.verify().is_ok());
    }

    #[test]
    fn commit_block_produces_no_network_command() {
        let block = Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                prev_block_hash: Hash256::ZERO,
                merkle_root: Hash256::ZERO,
                timestamp: 1_700_000_000,
                height: 1,
                tx_count: 0,
                validator_id: NoblePublicKey::Ed25519(vec![0; 32]),
                validator_sig: SignatureEnvelope {
                    scheme_id: 0,
                    public_key: vec![],
                    signature: vec![],
                },
            },
            transactions: vec![],
        };
        let cmds = cycle_io_to_network_commands(CycleIo::CommitBlock(Box::new(block)));
        assert!(cmds.is_empty());
    }
}
