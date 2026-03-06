// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Placeholder for the Contacts section (Sprint 5).
struct ContactsPlaceholder: View {
    var body: some View {
        ContentUnavailableView {
            Label("Contacts", systemImage: "person.2.fill")
        } description: {
            Text("Manage your NOBLE address book.")
        }
        .navigationTitle("Contacts")
    }
}
