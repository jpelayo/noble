// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Bridge between network events/commands and consensus engine events/actions.
//!
//! These functions translate between the `noble-network` wire types
//! (`NetworkCommand`, `NetworkEvent`) and the `noble-consensus` domain types
//! (`CycleEvent`, `CycleIo`).

use noble_codec::NobleCbor;
use noble_consensus::{CycleEvent, CycleIo, PorVote};
use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope};
use noble_network::{NetworkCommand, NetworkEvent};

/// Convert a `NetworkEvent` into a consensus `CycleEvent` (if applicable).
///
/// Returns `None` for events that don't map to consensus inputs
/// (e.g., `PeerConnected`, `PeerDisconnected`, `BlockAnnounced`).
pub fn network_event_to_cycle_event(event: &NetworkEvent) -> Option<CycleEvent> {
    match event {
        NetworkEvent::BlockReceived { peer_id, block } => Some(CycleEvent::BlockProposed {
            block: Box::new(block.clone()),
            from_peer: peer_id.clone(),
        }),
        NetworkEvent::VoteReceived {
            peer_id,
            cycle,
            candidate_hash,
            voter_id,
            signature,
            round,
        } => {
            let vote = wire_to_por_vote(*cycle, candidate_hash, voter_id, signature, *round)?;
            // AUD3-D9: Use transport PeerId (not voter_id from the vote payload)
            // so the consensus engine can compare against known peer identities.
            Some(CycleEvent::VoteReceived {
                vote,
                from_peer: peer_id.clone(),
            })
        }
        _ => None,
    }
}

/// Convert a consensus `CycleIo` action into zero or more `NetworkCommand`s.
///
/// Actions that are handled locally by the node (CommitBlock, ReadmitTransactions,
/// SetTimer, EmitMetric, Log) return an empty `Vec`.
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
                round: vote.round,
            }]
        }
        CycleIo::RequestBlockFromAll { block_hash } => {
            vec![NetworkCommand::RequestBlockFromAll {
                hash: *block_hash.as_bytes(),
            }]
        }
        CycleIo::BanPeer { peer_id, category, reason } => {
            vec![NetworkCommand::BanPeer { peer_id, category: category as u8, reason, evidence_hash: None }]
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
        CycleIo::PublishEvidence(evidence) => {
            vec![NetworkCommand::PublishEvidence(evidence)]
        }
        // CommitBlock, ReadmitTransactions, SetTimer, EmitMetric, Log
        // are handled locally by the node, not sent to the network.
        _ => vec![],
    }
}

/// Serialize a `PorVote`'s signature into wire bytes for network transmission.
///
/// Encodes the full `SignatureEnvelope` as CBOR.
pub fn vote_to_signature_bytes(vote: &PorVote) -> Vec<u8> {
    vote.signature.to_cbor().unwrap_or_default()
}

/// Reconstruct a `PorVote` from wire bytes received over the network.
///
/// Returns `None` if the voter public key or signature cannot be deserialized.
pub fn wire_to_por_vote(
    cycle: u64,
    candidate_hash: &[u8; 32],
    voter_id: &[u8],
    signature_bytes: &[u8],
    round: u8,
) -> Option<PorVote> {
    let voter_pubkey = NoblePublicKey::from_wire_bytes(voter_id).ok()?;
    let candidate_hash = Hash256(*candidate_hash);
    let signature = SignatureEnvelope::from_cbor(signature_bytes).ok()?;

    Some(PorVote {
        cycle,
        candidate_hash,
        voter_pubkey,
        signature,
        round,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{Block, BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{ed25519, NoblePrivateKey, SignatureEnvelope};

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
    fn broadcast_vote_converts_to_publish_vote() {
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

        let wire_voter_id = original.voter_pubkey.to_wire_bytes();
        let wire_sig = vote_to_signature_bytes(&original);
        let wire_hash = *original.candidate_hash.as_bytes();

        let recovered =
            wire_to_por_vote(5, &wire_hash, &wire_voter_id, &wire_sig, original.round).unwrap();
        assert_eq!(recovered.cycle, 5);
        assert_eq!(recovered.candidate_hash, original.candidate_hash);
        assert_eq!(recovered.round, 1);
        assert!(recovered.verify().is_ok());
    }

    #[test]
    fn vote_r2_roundtrip_wire_conversion() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let original = PorVote::sign_round(5, Hash256([0xBB; 32]), 2, &priv_key, pub_key).unwrap();

        let wire_voter_id = original.voter_pubkey.to_wire_bytes();
        let wire_sig = vote_to_signature_bytes(&original);
        let wire_hash = *original.candidate_hash.as_bytes();

        let recovered = wire_to_por_vote(5, &wire_hash, &wire_voter_id, &wire_sig, 2).unwrap();
        assert_eq!(recovered.round, 2);
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

    #[test]
    fn ban_peer_converts_to_ban_command() {
        let cmds = cycle_io_to_network_commands(CycleIo::BanPeer {
            peer_id: vec![1, 2, 3],
            category: noble_core::BanCategoryCode::ProtocolViolation,
            reason: "misbehavior".to_string(),
        });
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], NetworkCommand::BanPeer { .. }));
    }

    #[test]
    fn request_block_converts_to_request_command() {
        let cmds = cycle_io_to_network_commands(CycleIo::RequestBlock {
            peer_id: vec![1, 2, 3],
            block_hash: Hash256([0xFF; 32]),
        });
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], NetworkCommand::RequestBlock { .. }));
    }

    #[test]
    fn set_timer_produces_no_network_command() {
        let cmds = cycle_io_to_network_commands(CycleIo::SetTimer { duration_secs: 10 });
        assert!(cmds.is_empty());
    }

    #[test]
    fn block_received_converts_to_block_proposed() {
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
        let event = NetworkEvent::BlockReceived {
            peer_id: vec![1, 2, 3],
            block: block.clone(),
        };
        let cycle_event = network_event_to_cycle_event(&event);
        assert!(cycle_event.is_some());
        assert!(matches!(
            cycle_event.unwrap(),
            CycleEvent::BlockProposed { .. }
        ));
    }

    #[test]
    fn peer_connected_returns_none() {
        let event = NetworkEvent::PeerConnected {
            peer_id: vec![1],
            addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
            direction: "inbound".to_string(),
            chain_tip: None,
        };
        assert!(network_event_to_cycle_event(&event).is_none());
    }

    #[test]
    fn vote_received_converts_to_cycle_vote() {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let vote = PorVote::sign(3, Hash256([0xBB; 32]), &priv_key, pub_key.clone()).unwrap();

        let event = NetworkEvent::VoteReceived {
            cycle: vote.cycle,
            candidate_hash: *vote.candidate_hash.as_bytes(),
            voter_id: pub_key.to_wire_bytes(),
            signature: vote_to_signature_bytes(&vote),
            peer_id: vec![0xAA; 32],
            round: 1,
        };

        let cycle_event = network_event_to_cycle_event(&event);
        assert!(cycle_event.is_some());
        match cycle_event.unwrap() {
            CycleEvent::VoteReceived {
                vote: v,
                from_peer: _,
            } => {
                assert_eq!(v.cycle, 3);
                assert!(v.verify().is_ok());
            }
            _ => panic!("expected VoteReceived"),
        }
    }
}
