// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Live implementation of ``TransactionSigning`` using ``TransactionBuilder`` (UTXO model).
public struct LiveTransactionSigner: TransactionSigning {
    private let builder = TransactionBuilder()

    public init() {}

    public func signTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        feeRate: UInt64 = 0,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId
    ) throws -> String {
        try builder.buildTransfer(
            to: to,
            amount: amount,
            fee: fee,
            feeRate: feeRate,
            utxos: utxos,
            changeAddress: changeAddress,
            privateKey: privateKey,
            chainId: chainId
        )
    }

    public func signNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        feeRate: UInt64 = 0,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId
    ) throws -> String {
        try builder.buildNotarization(
            checksum: checksum,
            metadata: metadata,
            fee: fee,
            feeRate: feeRate,
            utxos: utxos,
            changeAddress: changeAddress,
            privateKey: privateKey,
            chainId: chainId
        )
    }
}
