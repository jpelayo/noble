// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_getBlock / noble_getLatestBlock

struct BlockDTO: Decodable, Sendable {
    let height: UInt64
    let hash: String?
    let prev_hash: String?
    let merkle_root: String?
    let timestamp: UInt64?
    let tx_count: UInt32?
    let validator_id: String?
    let transactions: [TransactionDTO]?
}

// MARK: - noble_getBlockHeader

struct BlockHeaderDTO: Decodable, Sendable {
    let height: UInt64
    let hash: String?
    let prev_hash: String?
    let merkle_root: String?
    let timestamp: UInt64?
    let tx_count: UInt32?
    let validator_id: String?
}

// MARK: - noble_getChainStats

struct ChainStatsDTO: Decodable, Sendable {
    let height: UInt64
    let total_transactions: UInt64?
    let chain_id: String?
}

// MARK: - noble_getPeerInfo

struct PeerInfoDTO: Decodable, Sendable {
    let peer_id: String
    let direction: String?
    let addr: String?
    let node_name: String?
    let country_code: String?
    let connected_at: UInt64?
    let ban_score: UInt32?
    let status: String?
    let chain_tip_height: UInt64?
    let chain_tip_hash: String?
}
