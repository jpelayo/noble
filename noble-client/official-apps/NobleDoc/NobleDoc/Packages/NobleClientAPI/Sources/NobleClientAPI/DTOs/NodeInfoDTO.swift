// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_getNodeInfo

/// Raw JSON-RPC response from `noble_getNodeInfo`.
struct NodeInfoDTO: Decodable, Sendable {
    let version: String?
    let software_version: String?
    let protocol_version: String?
    let chain_id: String?
    let network_name: String?
    let genesis_hash: String?
    let uptime_secs: UInt64?
    let rpc_port: UInt16?
    let ws_port: UInt16?
    let p2p_port: UInt16?
    let peer_id: String?
    let latest_network_version: String?
    let storage_bytes: UInt64?
    let storage_capacity_bytes: UInt64?
    let data_dir: String?
}

// MARK: - noble_getApiVersion

struct ApiVersionDTO: Decodable, Sendable {
    let api_version: String
    let method_count: Int?
}

// MARK: - noble_getBlockCount

struct BlockCountDTO: Decodable, Sendable {
    let height: UInt64
    let block_hash: String?
}

// MARK: - noble_getSyncStatus

struct SyncStatusDTO: Decodable, Sendable {
    let synced: Bool
    let current_height: UInt64
    let highest_known: UInt64?
    let progress: Double?
    let state: String?
}

// MARK: - noble_getCycleStatus

struct CycleStatusDTO: Decodable, Sendable {
    let cycle_number: UInt64
    let phase: String
    let phase_remaining_secs: UInt64?
    let cycle_remaining_secs: UInt64?
}

// MARK: - noble_getNetworkInfo

struct NetworkInfoDTO: Decodable, Sendable {
    let peer_count: Int
    let inbound: Int?
    let outbound: Int?
    let clock_offset_ms: Int64?
}

// MARK: - noble_getTlsCertInfo

struct TlsCertInfoDTO: Decodable, Sendable {
    let fingerprint: String?
    let expires_at: String?
    let subject: String?
    let sans: [String]?
    let is_self_signed: Bool?
    let mode: String?
}
