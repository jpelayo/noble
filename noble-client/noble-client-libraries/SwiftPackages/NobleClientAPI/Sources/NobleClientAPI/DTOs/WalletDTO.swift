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
    let immature_count: UInt64?
    let immature_value: UInt64?
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
    /// UTXO lifecycle: "available", "pending_spend", "immature".
    let status: String?
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
    let low_fee_rate: UInt64
    let recommended_fee_rate: UInt64
    let high_priority_fee_rate: UInt64
    let network_min_fee_rate: UInt64?
    let network_median_fee_rate: UInt64?
    let local_min_fee_rate: UInt64?
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

// MARK: - noble_getAddressPending

struct AddressPendingDTO: Decodable, Sendable {
    let address: String
    let count: Int
    let transactions: [PendingTxDTO]
}

struct PendingTxDTO: Decodable, Sendable {
    let tx_id: String
    let sent: UInt64
    let change: UInt64
    let fee: UInt64
    let net_debit: UInt64
    let confirmation_status: String?
}

// MARK: - noble_getWalletTransactions

struct WalletTransactionsDTO: Decodable, Sendable {
    let transactions: [WalletTxEntryDTO]
}

public struct WalletTxEntryDTO: Decodable, Sendable {
    public let tx_id: String
    public let tx_type: UInt8
    public let type_label: String?
    public let direction: String
    public let amount: UInt64
    public let transfer_value: UInt64?
    public let fee: UInt64?
    public let total_output: UInt64?
    public let confirmations: UInt64
    public let block_height: UInt64?
    public let timestamp: UInt64?
    public let counterparty: String?
    public let signer: String?
    public let status: String?
    public let checksum: String?
    public let inputs: [TxInputDTO]?
    public let outputs: [TxOutputDTO]?
    public let metadata: [MetadataDTO]?
    public let has_encrypted_locator: Bool?
}

// MARK: - noble_getWalletSnapshot

public struct WalletSnapshotDTO: Decodable, Sendable {
    public let chain_height: UInt64
    public let balance: UInt64
    public let available: UInt64
    public let pending: UInt64
    public let immature_count: UInt64?
    public let immature_value: UInt64?
    public let transactions: [WalletTxEntryDTO]
}
