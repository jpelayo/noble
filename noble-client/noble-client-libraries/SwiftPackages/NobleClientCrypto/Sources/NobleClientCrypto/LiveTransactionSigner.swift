// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Live implementation of ``TransactionSigning`` using ``TransactionBuilder``.
public struct LiveTransactionSigner: TransactionSigning {
    private let builder = TransactionBuilder()

    public init() {}

    public func signTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.mainnetChainId,
        sourceAddress: Data? = nil
    ) throws -> String {
        try builder.buildTransfer(
            to: to,
            amount: amount,
            fee: fee,
            privateKey: privateKey,
            chainId: chainId,
            sourceAddress: sourceAddress
        )
    }

    public func signNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.mainnetChainId
    ) throws -> String {
        try builder.buildNotarization(
            checksum: checksum,
            metadata: metadata,
            fee: fee,
            privateKey: privateKey,
            chainId: chainId
        )
    }
}
