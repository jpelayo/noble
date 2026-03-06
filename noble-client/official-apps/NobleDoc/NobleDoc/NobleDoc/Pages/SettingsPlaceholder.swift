// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Placeholder for the Settings section (Sprint 3).
struct SettingsPlaceholder: View {
    var body: some View {
        ContentUnavailableView {
            Label("Settings", systemImage: "gear")
        } description: {
            Text("Configure node connection and app preferences.")
        }
        .navigationTitle("Settings")
    }
}
