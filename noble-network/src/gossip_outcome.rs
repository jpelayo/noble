// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Gossip-handler outcome — communicates application-layer semantic
//! validation back to the gossipsub propagation gate.
//!
//! Background: libp2p's `ValidationMode::Strict` only validates the
//! gossip ENVELOPE (signature, sequence number). To gate APPLICATION
//! semantics (e.g. "this vote has a valid PoR signature", "this tx
//! announce is well-formed"), the application must:
//!   1. Configure gossipsub with `.validate_messages()` — defers the
//!      propagate decision until we report it.
//!   2. Return a typed outcome from each handler that distinguishes
//!      Accept (forward), Reject (penalize source + drop), and
//!      Ignore (drop silently, no penalty — for dedup hits etc.).
//!   3. Translate the outcome into [`libp2p::gossipsub::MessageAcceptance`]
//!      at the propagation point.
//!
//! This module defines that outcome type. The translation happens in
//! `service.rs` where `report_message_validation_result` is called.

use crate::messages::NetworkEvent;

/// Application-layer outcome of a gossip handler.
///
/// Variants:
/// - `Accept(event)` — message is valid; emit `event` to the consensus
///   layer AND tell gossipsub to propagate to other peers.
/// - `Reject(event)` — message is semantically invalid (bad signature,
///   malformed payload, etc.). Optionally emit `event` for local logging
///   /penalty wiring, and tell gossipsub to NOT propagate. Source peer
///   gets a reputation penalty from gossipsub.
/// - `Ignore` — benign drop (duplicate, rate-limited, already in-flight,
///   cross-chain announce). No event emitted; gossipsub treats source
///   as non-malicious and stops propagation.
///
/// `Reject` is reserved for cases where the message is *demonstrably
/// invalid*. Benign-but-uninteresting messages use `Ignore` to avoid
/// penalising honest peers for transient race conditions.
pub enum GossipOutcome {
    Accept(NetworkEvent),
    Reject(Option<NetworkEvent>),
    Ignore,
}

impl GossipOutcome {
    /// Convenience constructor for "valid, emit event, accept".
    pub fn accept(event: NetworkEvent) -> Self {
        Self::Accept(event)
    }

    /// Convenience constructor for "invalid, no event, reject".
    pub fn reject() -> Self {
        Self::Reject(None)
    }

    /// Convenience constructor for "invalid, emit event for logging,
    /// reject for propagation".
    pub fn reject_with(event: NetworkEvent) -> Self {
        Self::Reject(Some(event))
    }

    /// Convenience constructor for "benign drop, no event".
    pub fn ignore() -> Self {
        Self::Ignore
    }
}
