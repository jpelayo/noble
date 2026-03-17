// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_getWalletInfo

struct WalletInfoDTO: Decodable, Sendable {
    let unlocked: Bool?
    let expires_at: UInt64?
    let key_count: Int?
    let balance: UInt64?
    let available: UInt64?
    let pending: UInt64?
    let noble_balance: UInt64?
    let hash160_balance: UInt64?
    let taproot_balance: UInt64?
}

// MARK: - noble_getAddressBalance

struct AddressBalanceDTO: Decodable, Sendable {
    let public_key: String?
    let balance: UInt64
    let available: UInt64?
    let pending: UInt64?
    let tx_count: UInt64?
}

// MARK: - noble_getAddressUtxos

struct AddressUtxosDTO: Decodable, Sendable {
    let address: String?
    let utxos: [UtxoDTO]
}

struct UtxoDTO: Decodable, Sendable {
    let txid: String
    let vout: UInt32
    let value: UInt64
    let height: UInt64
    let is_coinbase: Bool
}

// MARK: - noble_getAddressHistory

struct AddressHistoryDTO: Decodable, Sendable {
    let public_key: String?
    let transactions: [String]
    let total: UInt64?
    let page: UInt32?
    let limit: UInt32?
}

// MARK: - noble_validateAddress

struct ValidateAddressDTO: Decodable, Sendable {
    let valid: Bool
    let scheme_id: UInt8?
    let address_type: String?
}

// MARK: - noble_estimateFee

struct FeeEstimateDTO: Decodable, Sendable {
    let min_fee: UInt64
    let recommended_fee: UInt64
    let high_priority_fee: UInt64
}

// MARK: - noble_getMempoolInfo

struct MempoolInfoDTO: Decodable, Sendable {
    let count: UInt64
    let total_bytes: UInt64?
    let min_fee: UInt64?
    let max_fee: UInt64?
    let avg_fee: UInt64?
}

// MARK: - noble_listAddresses

struct ListAddressesDTO: Decodable, Sendable {
    let keys: [AddressKeyDTO]?
}

struct AddressKeyDTO: Decodable, Sendable {
    let pubkey_hex: String
    let scheme: String?
    let bitcoin_addresses: [String]?
}
