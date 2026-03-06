// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! WebSocket subscription handlers (H-001).
//!
//! Exposes 4 subscription RPC methods using the broadcast channels from ApiState:
//! - `noble_subscribeNewBlocks` / `noble_unsubscribeNewBlocks`
//! - `noble_subscribeNewTransactions` / `noble_unsubscribeNewTransactions`
//! - `noble_subscribeCyclePhase` / `noble_unsubscribeCyclePhase`
//! - `noble_subscribePeerUpdates` / `noble_unsubscribePeerUpdates`

use std::sync::Arc;

use jsonrpsee::core::SubscriptionResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::PendingSubscriptionSink;
use tokio::sync::broadcast;

use noble_storage::StorageEngine;

use crate::state::ApiState;

#[rpc(server, namespace = "noble")]
pub trait SubscriptionApi {
    /// Subscribe to new block notifications.
    #[subscription(
        name = "subscribeNewBlocks",
        unsubscribe = "unsubscribeNewBlocks",
        item = serde_json::Value
    )]
    async fn subscribe_new_blocks(&self) -> SubscriptionResult;

    /// Subscribe to new transaction announcements.
    #[subscription(
        name = "subscribeNewTransactions",
        unsubscribe = "unsubscribeNewTransactions",
        item = serde_json::Value
    )]
    async fn subscribe_new_transactions(&self) -> SubscriptionResult;

    /// Subscribe to consensus cycle phase changes.
    #[subscription(
        name = "subscribeCyclePhase",
        unsubscribe = "unsubscribeCyclePhase",
        item = serde_json::Value
    )]
    async fn subscribe_cycle_phase(&self) -> SubscriptionResult;

    /// Subscribe to peer connect/disconnect events.
    #[subscription(
        name = "subscribePeerUpdates",
        unsubscribe = "unsubscribePeerUpdates",
        item = serde_json::Value
    )]
    async fn subscribe_peer_updates(&self) -> SubscriptionResult;
}

/// Receive from a broadcast channel, tolerating lag.
///
/// On `RecvError::Lagged(n)`, skips the missed messages and continues.
/// Returns `None` only when the channel is closed (all senders dropped).
async fn recv_tolerant(
    rx: &mut broadcast::Receiver<serde_json::Value>,
) -> Option<serde_json::Value> {
    loop {
        match rx.recv().await {
            Ok(msg) => return Some(msg),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::debug!(
                    task = "ws_subscription",
                    "broadcast receiver lagged, skipped {n} messages"
                );
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> SubscriptionApiServer for Arc<ApiState<S>> {
    async fn subscribe_new_blocks(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let mut rx = self.new_block_tx.subscribe();
        let sink = pending.accept().await?;
        tokio::spawn(async move {
            while let Some(msg) = recv_tolerant(&mut rx).await {
                if sink
                    .send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn subscribe_new_transactions(
        &self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let mut rx = self.new_tx_tx.subscribe();
        let sink = pending.accept().await?;
        tokio::spawn(async move {
            while let Some(msg) = recv_tolerant(&mut rx).await {
                if sink
                    .send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn subscribe_cycle_phase(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let mut rx = self.cycle_phase_tx.subscribe();
        let sink = pending.accept().await?;
        tokio::spawn(async move {
            while let Some(msg) = recv_tolerant(&mut rx).await {
                if sink
                    .send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn subscribe_peer_updates(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let mut rx = self.peer_update_tx.subscribe();
        let sink = pending.accept().await?;
        tokio::spawn(async move {
            while let Some(msg) = recv_tolerant(&mut rx).await {
                if sink
                    .send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }
}
