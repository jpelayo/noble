// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Top-level navigation sections in the sidebar.
enum SidebarSection: String, CaseIterable, Identifiable {
    case documents
    case payments
    case contacts
    case settings

    var id: String { rawValue }

    var label: String {
        switch self {
        case .documents: "Documents"
        case .payments: "Payments"
        case .contacts: "Contacts"
        case .settings: "Settings"
        }
    }

    var systemImage: String {
        switch self {
        case .documents: "doc.text.fill"
        case .payments: "creditcard.fill"
        case .contacts: "person.2.fill"
        case .settings: "gear"
        }
    }
}
