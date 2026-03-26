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

struct WalletTxEntryDTO: Decodable, Sendable {
    let tx_id: String
    let tx_type: UInt8
    let type_label: String?
    let direction: String
    let amount: UInt64
    let transfer_value: UInt64?
    let fee: UInt64?
    let total_output: UInt64?
    let confirmations: UInt64
    let block_height: UInt64?
    let timestamp: UInt64?
    let counterparty: String?
    let signer: String?
    let status: String?
    let checksum: String?
    let inputs: [TxInputDTO]?
    let outputs: [TxOutputDTO]?
    let metadata: [MetadataDTO]?
    let has_encrypted_locator: Bool?
}
