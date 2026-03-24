// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC client for communicating with a Noble node.
//!
//! Mirrors the Swift `LiveNobleAPIService` + `JSONRPCClient`. All 18 bridge
//! actions from `noble_api` are mapped to their RPC methods.

use reqwest::Client;
use serde_json::{json, Value};

/// JSON-RPC client wrapping reqwest with Noble-specific configuration.
pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    /// Create a new API client for the given node URL.
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true) // Self-signed node certs
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Execute a JSON-RPC 2.0 call.
    pub async fn call_rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Gatekeeper", "noble")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Connection failed: {e} [{}]", crate::errors::NE_NODE_UNREACHABLE))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {e} [{}]", crate::errors::NE_INVALID_RESPONSE))?;

        if !status.is_success() {
            return Err(format!("HTTP {status}: {text} [{}]", crate::errors::NE_HTTP_ERROR));
        }

        let rpc_response: Value =
            serde_json::from_str(&text).map_err(|e| format!("Invalid JSON response: {e} [{}]", crate::errors::NE_INVALID_RESPONSE))?;

        if let Some(error) = rpc_response.get("error") {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown RPC error");
            return Err(msg.to_string());
        }

        Ok(rpc_response
            .get("result")
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// Faucet HTTP GET (separate endpoint, port 8786).
    pub async fn faucet_status(&self, faucet_base: &str) -> Result<Value, String> {
        let url = format!("{}/api/faucet/status", faucet_base.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| "Faucet service is not available".to_string())?;

        if !resp.status().is_success() {
            return Err("Faucet service is not available".to_string());
        }

        resp.json::<Value>()
            .await
            .map_err(|_| "Faucet service is not available".to_string())
    }

    /// Faucet HTTP POST (separate endpoint, port 8786).
    pub async fn faucet_request(&self, faucet_base: &str, address: &str) -> Result<Value, String> {
        let url = format!("{}/api/faucet", faucet_base.trim_end_matches('/'));
        let body = json!({ "address": address });

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| "Faucet service is not available".to_string())?;

        let status = resp.status();
        let json_resp: Value = resp
            .json()
            .await
            .map_err(|_| "Faucet service is not available".to_string())?;

        if status.as_u16() == 429 || status.is_client_error() || status.is_server_error() {
            let msg = json_resp
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Faucet request failed");
            return Err(msg.to_string());
        }

        Ok(json_resp)
    }
}

/// Derive faucet base URL from node URL (same host, port 8786).
pub fn faucet_base_url(node_url: &str) -> Option<String> {
    // Parse host from URL like "https://1.2.3.4:8783" or "https://localhost:8783"
    let url = reqwest::Url::parse(node_url).ok()?;
    let host = url.host_str()?;
    Some(format!("http://{}:8786", host))
}

/// Handle all `noble_api` bridge actions.
///
/// Maps each action to the corresponding JSON-RPC method call.
pub async fn handle_api_action(
    client: &ApiClient,
    action: &str,
    params: &Value,
    node_url: &str,
    wallet_address: &str,
    block_height: u64,
) -> Result<Value, String> {
    match action {
        "getBalance" => {
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: address")?;
            let result = client
                .call_rpc("noble_getWalletInfo", json!([address]))
                .await?;
            // Extract and reshape to match bridge contract
            Ok(json!({
                "address": result.get("address").and_then(|v| v.as_str()).unwrap_or(address),
                "balance": result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0),
                "available": result.get("available").and_then(|v| v.as_u64())
                    .or_else(|| result.get("balance").and_then(|v| v.as_u64()))
                    .unwrap_or(0),
                "pending": result.get("pending").and_then(|v| v.as_u64()).unwrap_or(0),
                "txCount": result.get("tx_count").or(result.get("txCount"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        }

        "getSyncStatus" => {
            let result = client
                .call_rpc("noble_getSyncStatus", json!([]))
                .await?;
            Ok(json!({
                "synced": result.get("synced").and_then(|v| v.as_bool()).unwrap_or(false),
                "currentHeight": result.get("current_height")
                    .or(result.get("currentHeight"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "highestKnown": result.get("highest_known")
                    .or(result.get("highestKnown"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "progress": result.get("progress").and_then(|v| v.as_f64()).unwrap_or(1.0),
            }))
        }

        "getCycleStatus" => {
            let result = client
                .call_rpc("noble_getCycleStatus", json!([]))
                .await?;
            Ok(json!({
                "cycleNumber": result.get("cycle_number")
                    .or(result.get("cycleNumber"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "phase": result.get("phase").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                "phaseRemainingSecs": result.get("phase_remaining_secs")
                    .or(result.get("phaseRemainingSecs"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "cycleRemainingSecs": result.get("cycle_remaining_secs")
                    .or(result.get("cycleRemainingSecs"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        }

        "getWalletTransactions" | "getTransactionHistory" => {
            // Pass client wallet address so server includes client-key txs.
            let addresses_param = if !wallet_address.is_empty() {
                json!([vec![wallet_address]])
            } else {
                json!([null])
            };
            let mut result = client
                .call_rpc("noble_getWalletTransactions", addresses_param)
                .await?;

            // Compose: fetch CLIENT's own pending mempool txs.
            if !wallet_address.is_empty() {
                if let Ok(pending_result) = client.call_rpc("noble_getAddressPending", json!([wallet_address])).await {
                    if let Some(pending_txs) = pending_result.get("transactions").and_then(|v| v.as_array()) {
                        let confirmed_ids: std::collections::HashSet<String> = result
                            .get("transactions").and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|t| t.get("tx_id").and_then(|v| v.as_str()).map(String::from)).collect())
                            .unwrap_or_default();

                        let mut pending_entries: Vec<Value> = Vec::new();
                        for p in pending_txs {
                            let tx_id = p.get("tx_id").and_then(|v| v.as_str()).unwrap_or("");
                            if confirmed_ids.contains(tx_id) { continue; }
                            let sent = p.get("sent").and_then(|v| v.as_u64()).unwrap_or(0);
                            let fee = p.get("fee").and_then(|v| v.as_u64()).unwrap_or(0);
                            let change = p.get("change").and_then(|v| v.as_u64()).unwrap_or(0);
                            let net_debit = p.get("net_debit").and_then(|v| v.as_u64()).unwrap_or(0);
                            let is_transfer = sent > 0;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default().as_secs();
                            pending_entries.push(json!({
                                "txId": tx_id,
                                "tx_type": if is_transfer { 1 } else { 0 },
                                "type": if is_transfer { "Pending Transfer" } else { "Pending Notarization" },
                                "direction": "outgoing",
                                "amount": net_debit,
                                "fee": fee,
                                "status": "pending",
                                "confirmations": 0,
                                "counterparty": if is_transfer { "Transfer" } else { "Self (Document)" },
                                "total_output": change + sent,
                                "transfer_value": sent,
                                "timestamp": now,
                            }));
                        }

                        if !pending_entries.is_empty() {
                            if let Some(txs) = result.get_mut("transactions").and_then(|v| v.as_array_mut()) {
                                for entry in pending_entries.into_iter().rev() {
                                    txs.insert(0, entry);
                                }
                            }
                        }
                    }
                }
            }

            Ok(result)
        }

        "estimateFee" => {
            let result = client
                .call_rpc("noble_estimateFee", json!([]))
                .await?;
            // Pass through rate-based fields. Client computes total = rate × tx_size.
            let est_tx_size: u64 = 300; // typical tx ~300 bytes
            let low = result.get("low_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1);
            let med = result.get("recommended_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1);
            let high = result.get("high_priority_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1);
            Ok(json!({
                "minFee": low * est_tx_size,
                "recommendedFee": med * est_tx_size,
                "highPriorityFee": high * est_tx_size,
                "lowFeeRate": low,
                "recommendedFeeRate": med,
                "highPriorityFeeRate": high,
                "networkMinFeeRate": result.get("network_min_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1),
                "networkMedianFeeRate": result.get("network_median_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1),
                "localMinFeeRate": result.get("local_min_fee_rate").and_then(|v| v.as_u64()).unwrap_or(1),
            }))
        }

        "verifyDocument" => {
            let checksum = params
                .get("checksum")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: checksum")?;
            let result = client
                .call_rpc("noble_lookupChecksum", json!([checksum]))
                .await?;
            Ok(result)
        }

        "getDocumentVersions" => {
            let checksum = params
                .get("checksum")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: checksum")?;
            let result = client
                .call_rpc("noble_lookupChecksum", json!([checksum]))
                .await?;
            Ok(json!({
                "checksum": checksum,
                "versions": result.get("records").or(result.get("versions"))
                    .cloned().unwrap_or(json!([])),
            }))
        }

        "submitTransaction" => {
            let raw_hex = params
                .get("rawHex")
                .or_else(|| params.get("txHex"))
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: rawHex")?;
            let result = client
                .call_rpc("noble_submitTransaction", json!([raw_hex]))
                .await?;
            let tx_id = result
                .get("tx_id")
                .or(result.get("txId"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Ok(json!({
                "txId": tx_id,
                "accepted": true,
            }))
        }

        "getNodeInfo" => {
            let result = client
                .call_rpc("noble_getNodeInfo", json!([]))
                .await?;
            Ok(json!({
                "chainId": result.get("chain_id").or(result.get("chainId"))
                    .and_then(|v| v.as_str()).unwrap_or(""),
                "version": result.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                "blockHeight": result.get("block_height").or(result.get("blockHeight"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "peerCount": result.get("peer_count").or(result.get("peerCount"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
                "isSyncing": result.get("is_syncing").or(result.get("isSyncing"))
                    .and_then(|v| v.as_bool()).unwrap_or(false),
            }))
        }

        "getBlockCount" => {
            let result = client
                .call_rpc("noble_getNodeInfo", json!([]))
                .await?;
            Ok(json!({
                "height": result.get("block_height").or(result.get("blockHeight"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        }

        "getNetworkInfo" => {
            let peers_result = client
                .call_rpc("noble_getPeers", json!([]))
                .await
                .unwrap_or(json!([]));
            let peers = peers_result.as_array().cloned().unwrap_or_default();
            let inbound = peers
                .iter()
                .filter(|p| p.get("direction").and_then(|d| d.as_str()) == Some("inbound"))
                .count();
            let outbound = peers.len() - inbound;

            let network_info = client
                .call_rpc("noble_getNetworkInfo", json!([]))
                .await
                .unwrap_or(json!({}));
            let clock_offset = network_info
                .get("clock_offset_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            Ok(json!({
                "peer_count": peers.len(),
                "inbound": inbound,
                "outbound": outbound,
                "clock_offset_ms": clock_offset,
            }))
        }

        "getPeers" => {
            let result = client
                .call_rpc("noble_getPeers", json!([]))
                .await?;
            let peers = result.as_array().cloned().unwrap_or_default();
            let inbound = peers
                .iter()
                .filter(|p| p.get("direction").and_then(|d| d.as_str()) == Some("inbound"))
                .count();
            let outbound = peers.len() - inbound;

            let peer_list: Vec<Value> = peers
                .iter()
                .map(|p| {
                    json!({
                        "peerId": p.get("peer_id").or(p.get("peerId"))
                            .and_then(|v| v.as_str()).unwrap_or(""),
                        "direction": p.get("direction").and_then(|v| v.as_str()).unwrap_or(""),
                        "address": p.get("address").and_then(|v| v.as_str()).unwrap_or(""),
                        "nodeName": p.get("node_name").or(p.get("nodeName"))
                            .and_then(|v| v.as_str()).unwrap_or(""),
                        "countryCode": p.get("country_code").or(p.get("countryCode"))
                            .and_then(|v| v.as_str()).unwrap_or(""),
                        "chainTipHeight": p.get("chain_tip_height").or(p.get("chainTipHeight"))
                            .and_then(|v| v.as_u64()),
                    })
                })
                .collect();

            Ok(json!({
                "total": peers.len(),
                "inbound": inbound,
                "outbound": outbound,
                "peers": peer_list,
            }))
        }

        "getTransaction" => {
            let tx_id = params
                .get("txId")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: txId")?;
            let result = client
                .call_rpc("noble_getTransaction", json!([tx_id]))
                .await?;
            Ok(enrich_transaction(&result, wallet_address, block_height))
        }

        "getTransactionStatus" => {
            let tx_id = params
                .get("txId")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: txId")?;
            let result = client
                .call_rpc("noble_getTransactionStatus", json!([tx_id]))
                .await?;
            Ok(json!({
                "status": result.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
            }))
        }

        "lookupChecksum" => {
            let checksum = params
                .get("checksum")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: checksum")?;
            let result = client
                .call_rpc("noble_lookupChecksum", json!([checksum]))
                .await?;
            let records = result
                .get("records")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            Ok(json!({
                "found": !records.is_empty(),
                "records": records,
            }))
        }

        "validateAddress" => {
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: address")?;
            let result = client
                .call_rpc("noble_validateAddress", json!([address]))
                .await?;
            Ok(json!({
                "valid": result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false),
            }))
        }

        "getAddressUtxos" => {
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: address")?;
            let result = client
                .call_rpc("noble_getAddressUtxos", json!([address]))
                .await?;
            // Pass through directly — field names match the bridge contract.
            Ok(result)
        }

        "faucetStatus" => {
            let faucet_base =
                faucet_base_url(node_url).ok_or("Faucet service is not available")?;
            client.faucet_status(&faucet_base).await
        }

        "faucetRequest" => {
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: address")?;
            let faucet_base =
                faucet_base_url(node_url).ok_or("Faucet service is not available")?;
            client.faucet_request(&faucet_base, address).await
        }

        "getAvailableFaucets" => {
            let result = client.call_rpc("noble_getAvailableFaucets", serde_json::json!([])).await?;
            Ok(result)
        }

        "faucetHopRequest" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: url")?;
            let address = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: address")?;
            client.faucet_request(url, address).await
        }

        // ── Governance RPCs (badge + DAO) ──
        "getBadgeHolders" | "getActiveProposals" | "getMyBadgeStatus"
        | "getActivePolls" => {
            client.call_rpc(&format!("noble_{action}"), serde_json::json!([])).await
        }

        "getProposalHistory" | "getPollHistory" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50);
            client.call_rpc(&format!("noble_{action}"), serde_json::json!([limit])).await
        }

        "proposeBadge" | "voteBadgeProposal" | "createPoll" | "votePoll" => {
            client.call_rpc(&format!("noble_{action}"), serde_json::json!([params])).await
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}

/// Enrich a raw transaction record with direction/counterparty/confirmations
/// for WebUI display, matching Swift's `txToDict()`.
fn enrich_transaction(tx: &Value, wallet_address: &str, tip_height: u64) -> Value {
    let mut dict = tx.clone();

    // Ensure standard field names
    if let Some(obj) = dict.as_object_mut() {
        // Normalize tx_type/txType → type
        let tx_type = obj
            .get("tx_type")
            .or(obj.get("txType"))
            .or(obj.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        obj.insert("type".to_string(), json!(tx_type));

        let signer = obj
            .get("signer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let outputs = obj
            .get("outputs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let first_output_addr = outputs
            .first()
            .and_then(|o| o.get("address"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if tx_type == "transfer" {
            if signer == wallet_address {
                obj.insert("direction".to_string(), json!("outgoing"));
                let counterparty = outputs
                    .iter()
                    .find(|o| {
                        o.get("address").and_then(|v| v.as_str()) != Some(wallet_address)
                    })
                    .and_then(|o| o.get("address"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(first_output_addr);
                obj.insert("counterparty".to_string(), json!(counterparty));
            } else {
                obj.insert("direction".to_string(), json!("incoming"));
                obj.insert("counterparty".to_string(), json!(signer));
            }
        }

        // Confirmations
        let tx_height = obj
            .get("blockHeight")
            .or(obj.get("block_height"))
            .and_then(|v| v.as_u64());
        if let Some(h) = tx_height {
            let confs = if tip_height >= h {
                tip_height - h + 1
            } else {
                0
            };
            obj.insert("confirmations".to_string(), json!(confs));
        } else {
            obj.insert("confirmations".to_string(), json!(0));
        }
    }

    dict
}
