// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_getNodeInfo

/// Raw JSON-RPC response from `noble_getNodeInfo`.
///
/// The node may return `chain_id` as either a string or an integer,
/// and `protocol_version` as either a string or an integer.
/// Custom decoding handles both representations.
struct NodeInfoDTO: Sendable {
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

extension NodeInfoDTO: Decodable {
    private enum CodingKeys: String, CodingKey {
        case version, software_version, protocol_version, chain_id, network_name
        case genesis_hash, uptime_secs, rpc_port, ws_port, p2p_port, peer_id
        case latest_network_version, storage_bytes, storage_capacity_bytes, data_dir
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decodeIfPresent(String.self, forKey: .version)
        software_version = try c.decodeIfPresent(String.self, forKey: .software_version)
        genesis_hash = try c.decodeIfPresent(String.self, forKey: .genesis_hash)
        uptime_secs = try c.decodeIfPresent(UInt64.self, forKey: .uptime_secs)
        rpc_port = try c.decodeIfPresent(UInt16.self, forKey: .rpc_port)
        ws_port = try c.decodeIfPresent(UInt16.self, forKey: .ws_port)
        p2p_port = try c.decodeIfPresent(UInt16.self, forKey: .p2p_port)
        peer_id = try c.decodeIfPresent(String.self, forKey: .peer_id)
        latest_network_version = try c.decodeIfPresent(String.self, forKey: .latest_network_version)
        storage_bytes = try c.decodeIfPresent(UInt64.self, forKey: .storage_bytes)
        storage_capacity_bytes = try c.decodeIfPresent(UInt64.self, forKey: .storage_capacity_bytes)
        data_dir = try c.decodeIfPresent(String.self, forKey: .data_dir)
        network_name = try c.decodeIfPresent(String.self, forKey: .network_name)

        // chain_id: node sends integer (e.g. 3104764622), decode as either String or UInt64→hex
        if let s = try? c.decodeIfPresent(String.self, forKey: .chain_id) {
            chain_id = s
        } else if let n = try? c.decodeIfPresent(UInt64.self, forKey: .chain_id) {
            chain_id = String(format: "%08X", n)
        } else {
            chain_id = nil
        }

        // protocol_version: node sends integer, decode flexibly
        if let s = try? c.decodeIfPresent(String.self, forKey: .protocol_version) {
            protocol_version = s
        } else if let n = try? c.decodeIfPresent(UInt64.self, forKey: .protocol_version) {
            protocol_version = String(n)
        } else {
            protocol_version = nil
        }
    }
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
