// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Placeholder for the Documents section (Sprint 2).
struct DocumentsPlaceholder: View {
    var body: some View {
        ContentUnavailableView {
            Label("Documents", systemImage: "doc.text.fill")
        } description: {
            Text("Register and verify documents on the NOBLE blockchain.")
        }
        .navigationTitle("Documents")
    }
}
