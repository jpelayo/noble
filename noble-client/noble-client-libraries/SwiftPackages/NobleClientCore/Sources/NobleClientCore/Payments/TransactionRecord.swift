// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A UTXO input reference.
public struct TxInput: Codable, Equatable, Sendable {
    public let txid: String
    public let vout: UInt32

    public init(txid: String, vout: UInt32) {
        self.txid = txid
        self.vout = vout
    }
}

/// A UTXO output.
public struct TxOutput: Codable, Equatable, Sendable {
    public let value: UInt64
    public let address: String

    public init(value: UInt64, address: String) {
        self.value = value
        self.address = address
    }
}

/// A transaction as returned by the node (UTXO model).
public struct TransactionRecord: Codable, Equatable, Sendable, Identifiable {
    public var id: String { txId.hex }
    public let txId: Hash256
    public let txType: TransactionType
    public let status: TransactionStatus
    public let signer: NobleAddress
    /// Total output value across all outputs.
    public let totalOutput: UInt64
    /// Inputs: references to spent UTXOs.
    public let inputs: [TxInput]
    /// Outputs: new UTXOs created.
    public let outputs: [TxOutput]
    public let blockHeight: UInt64?
    public let timestamp: Date?
    public let checksum: Hash256?
    /// Transaction fee in groats (computed from inputs - outputs).
    public let fee: UInt64?
    /// Net transfer value (outputs NOT going back to signer).
    public let transferValue: UInt64?
    /// User metadata attached to the transaction.
    public let metadata: [MetadataItem]?
    /// Whether the transaction has an encrypted locator.
    public let hasEncryptedLocator: Bool
    /// Number of confirmations (tip_height - tx_height + 1).
    public let confirmations: UInt64?
    /// Direction from server: "incoming", "outgoing", "self".
    public let direction: String?
    /// Display amount from server (groats).
    public let displayAmount: UInt64?
    /// Counterparty address from server (bech32m or display string).
    public let recipient: String?
    /// Type label from server (e.g. "Pending Notarization", "Transfer").
    public let typeLabel: String?

    public init(
        txId: Hash256,
        txType: TransactionType,
        status: TransactionStatus,
        signer: NobleAddress,
        totalOutput: UInt64 = 0,
        inputs: [TxInput] = [],
        outputs: [TxOutput] = [],
        blockHeight: UInt64? = nil,
        timestamp: Date? = nil,
        checksum: Hash256? = nil,
        fee: UInt64? = nil,
        transferValue: UInt64? = nil,
        metadata: [MetadataItem]? = nil,
        hasEncryptedLocator: Bool = false,
        confirmations: UInt64? = nil,
        direction: String? = nil,
        displayAmount: UInt64? = nil,
        recipient: String? = nil,
        typeLabel: String? = nil
    ) {
        self.txId = txId
        self.txType = txType
        self.status = status
        self.signer = signer
        self.totalOutput = totalOutput
        self.inputs = inputs
        self.outputs = outputs
        self.blockHeight = blockHeight
        self.timestamp = timestamp
        self.checksum = checksum
        self.fee = fee
        self.transferValue = transferValue
        self.metadata = metadata
        self.hasEncryptedLocator = hasEncryptedLocator
        self.confirmations = confirmations
        self.direction = direction
        self.displayAmount = displayAmount
        self.recipient = recipient
        self.typeLabel = typeLabel
    }
}
