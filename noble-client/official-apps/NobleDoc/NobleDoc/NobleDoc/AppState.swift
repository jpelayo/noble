// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Global app state shared across the view hierarchy.
@Observable
@MainActor
final class AppState {
    /// Currently selected sidebar section.
    var selectedSection: SidebarSection? = .documents

    /// Whether the app is connected to a NOBLE node.
    var isConnected = false

    /// Network label reported by the node (e.g. "testnet", "mainnet").
    var networkLabel = ""

    /// Current block height from the connected node.
    var blockHeight: UInt64 = 0

    /// Node base URL for JSON-RPC.
    var nodeURL = "https://localhost:8783"
}
