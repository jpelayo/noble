// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_submitTransaction

struct SubmitTransactionParams: Encodable, Sendable {
    let tx_hex: String
}

struct SubmitTxDTO: Decodable, Sendable {
    let tx_id: String?
    let accepted: Bool?
}

// MARK: - noble_getTransaction

struct GetTransactionParams: Encodable, Sendable {
    let tx_id: String
}

struct TxInputDTO: Decodable, Sendable {
    let txid: String
    let vout: UInt32
}

struct TxOutputDTO: Decodable, Sendable {
    let value: UInt64
    let address: String
}

struct TransactionDTO: Decodable, Sendable {
    let tx_id: String?
    let tx_type: UInt8?
    let checksum: String?
    let timestamp: UInt64?
    let total_output: UInt64?
    let transfer_value: UInt64?
    let fee: UInt64?
    let inputs: [TxInputDTO]?
    let outputs: [TxOutputDTO]?
    let signer: String?
    let metadata: [MetadataDTO]?
    let has_encrypted_locator: Bool?
    let attestation_count: Int?
}

struct MetadataDTO: Decodable, Sendable {
    let key: String
    let value: String
}

// MARK: - noble_getTransactionStatus

struct TransactionStatusDTO: Decodable, Sendable {
    let tx_id: String?
    let status: String
}

// MARK: - noble_getTransactionReceipt

struct TransactionReceiptDTO: Decodable, Sendable {
    let transaction: TransactionDTO?
    let status: String?
    let block_height: UInt64?
    let block_hash: String?
    let tx_index: UInt32?
    let confirmations: UInt64?
}
