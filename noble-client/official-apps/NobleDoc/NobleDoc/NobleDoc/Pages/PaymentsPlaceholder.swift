// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Placeholder for the Payments section (Sprint 4).
struct PaymentsPlaceholder: View {
    var body: some View {
        ContentUnavailableView {
            Label("Payments", systemImage: "creditcard.fill")
        } description: {
            Text("Send and receive NOBLE tokens.")
        }
        .navigationTitle("Payments")
    }
}
