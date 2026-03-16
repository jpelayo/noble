// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Axum request handlers for the faucet API.
//!
//! All SQLite database calls are dispatched to `tokio::task::spawn_blocking`
//! to avoid blocking async worker threads (M-004 audit fix).

use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::FaucetState;

/// POST /api/faucet — request NOBLE tokens.
#[derive(Deserialize)]
pub struct FaucetRequest {
    /// Target NOBLE address (hex-encoded public key).
    pub address: String,
}

#[derive(Serialize)]
pub struct FaucetResponse {
    pub success: bool,
    pub tx_id: Option<String>,
    pub amount: u64,
    pub message: String,
}

#[derive(Serialize)]
pub struct FaucetStatusResponse {
    pub network: String,
    pub faucet_address: String,
    pub faucet_balance: u64,
    pub total_distributed: u64,
    pub today_distributed: u64,
    pub distribution_count: u64,
    pub drip_amount: u64,
    pub ip_cooldown_hours: u64,
    pub address_cooldown_hours: u64,
    pub daily_cap: u64,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub message: String,
}

fn error_json(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorResponse {
            success: false,
            message: msg.to_string(),
        }),
    )
}

fn internal_error(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            success: false,
            message: msg.to_string(),
        }),
    )
}

/// Helper: run a blocking DB closure on the blocking threadpool.
async fn db_blocking<F, T>(f: F) -> Result<T, (StatusCode, Json<ErrorResponse>)>
where
    F: FnOnce() -> Result<T, crate::FaucetError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal_error(&format!("db task join: {e}")))?
        .map_err(|e| internal_error(&e.to_string()))
}

/// POST /api/faucet
pub async fn handle_faucet(
    State(state): State<Arc<FaucetState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<FaucetRequest>,
) -> Result<Json<FaucetResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ip = addr.ip().to_string();

    // Validate address format (must be hex, 66 or 68 chars for Ed25519/secp256k1).
    if req.address.len() < 64
        || req.address.len() > 68
        || !req.address.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                message: "Invalid NOBLE address format".to_string(),
            }),
        ));
    }

    // Rate limit: per-IP cooldown (24h default).
    {
        let db = state.db.clone();
        let ip_clone = ip.clone();
        let cooldown = state.config.ip_cooldown_secs;
        let is_limited =
            db_blocking(move || db.ip_recent_distribution(&ip_clone, cooldown)).await?;
        if is_limited {
            return Err(error_json(&format!(
                "Rate limited: try again in {} hours",
                state.config.ip_cooldown_secs / 3600
            )));
        }
    }

    // Rate limit: per-address cooldown (7d default).
    {
        let db = state.db.clone();
        let address = req.address.clone();
        let cooldown = state.config.address_cooldown_secs;
        let is_limited =
            db_blocking(move || db.address_recent_distribution(&address, cooldown)).await?;
        if is_limited {
            return Err(error_json(&format!(
                "This address already received tokens. Try again in {} days",
                state.config.address_cooldown_secs / 86400
            )));
        }
    }

    // Daily cap check.
    let today = {
        let db = state.db.clone();
        db_blocking(move || db.today_distributed()).await?
    };
    if today + state.config.drip_amount > state.config.daily_cap {
        return Err(error_json("Daily faucet cap reached. Try again tomorrow"));
    }

    // Send transfer: local signing (preferred) or node RPC (legacy fallback).
    let tx_id = if let Some(ref wallet) = state.wallet {
        // Get current chain height for coinbase maturity filtering
        let chain_height = state.rpc.get_node_info()
            .await
            .map(|info| info.block_height)
            .unwrap_or(0);
        // Build and sign locally, then submit raw transaction.
        let fee = noble_core::MIN_TX_FEE;
        let tx_hex = wallet
            .build_transfer(&state.rpc, &req.address, state.config.drip_amount, fee, chain_height)
            .await
            .map_err(|e| internal_error(&format!("Build transfer: {e}")))?;
        state
            .rpc
            .submit_raw_transaction(&tx_hex)
            .await
            .map_err(|e| internal_error(&format!("Submit failed: {e}")))?
    } else {
        // Legacy: delegate to node's walletSendTransfer RPC.
        state
            .rpc
            .send_transfer(
                &state.config.faucet_address,
                &req.address,
                state.config.drip_amount,
            )
            .await
            .map_err(|e| internal_error(&format!("Transfer failed: {e}")))?
    };

    // Record in DB.
    {
        let db = state.db.clone();
        let address = req.address.clone();
        let ip_clone = ip.clone();
        let amount = state.config.drip_amount;
        let tx_id_clone = tx_id.clone();
        db_blocking(move || {
            db.record_distribution(&address, &ip_clone, amount, Some(&tx_id_clone))
        })
        .await?;
    }

    tracing::info!(
        address = %req.address,
        ip = %ip,
        amount = state.config.drip_amount,
        tx_id = %tx_id,
        "Faucet distribution"
    );

    Ok(Json(FaucetResponse {
        success: true,
        tx_id: Some(tx_id),
        amount: state.config.drip_amount,
        message: format!(
            "Sent {} NOBLE to {}",
            state.config.drip_amount as f64 / 1_000_000.0,
            &req.address[..16]
        ),
    }))
}

/// GET /api/faucet/status
pub async fn handle_status(
    State(state): State<Arc<FaucetState>>,
) -> Result<Json<FaucetStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let total = {
        let db = state.db.clone();
        db_blocking(move || db.total_distributed()).await?
    };
    let today = {
        let db = state.db.clone();
        db_blocking(move || db.today_distributed()).await?
    };
    let count = {
        let db = state.db.clone();
        db_blocking(move || db.distribution_count()).await?
    };

    // Try to fetch live balance from node; fall back to 0 on error.
    let balance = state
        .rpc
        .get_balance(&state.config.faucet_address)
        .await
        .map(|b| b.available)
        .unwrap_or(0);

    // Ensure address is in bech32m format (nbl1...).
    let display_address = if state.config.faucet_address.starts_with("nbl1") {
        state.config.faucet_address.clone()
    } else {
        // Try hex wire bytes → bech32m conversion.
        hex::decode(&state.config.faucet_address)
            .ok()
            .and_then(|bytes| noble_crypto::noble_addr::encode_wire_bytes(&bytes))
            .unwrap_or_else(|| state.config.faucet_address.clone())
    };

    Ok(Json(FaucetStatusResponse {
        network: state.network.clone(),
        faucet_address: display_address,
        faucet_balance: balance,
        total_distributed: total,
        today_distributed: today,
        distribution_count: count,
        drip_amount: state.config.drip_amount,
        ip_cooldown_hours: state.config.ip_cooldown_secs / 3600,
        address_cooldown_hours: state.config.address_cooldown_secs / 3600,
        daily_cap: state.config.daily_cap,
    }))
}
