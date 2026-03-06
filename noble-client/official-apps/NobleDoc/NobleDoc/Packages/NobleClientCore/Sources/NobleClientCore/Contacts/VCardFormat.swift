// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Parser and serializer for vCard v3.0 format with NOBLE extensions.
///
/// Custom fields:
/// - `X-NOBLE-PUBKEY` — NOBLE public key in wire-hex
/// - `X-NOBLE-BTCKEY` — Bitcoin address
public enum VCardFormat {

    /// Parse a vCard string into contacts.
    public static func parse(_ vcf: String) -> [Contact] {
        var contacts: [Contact] = []
        var lines: [String] = []
        var inCard = false

        for line in vcf.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.uppercased() == "BEGIN:VCARD" {
                inCard = true
                lines = []
            } else if trimmed.uppercased() == "END:VCARD", inCard {
                inCard = false
                if let contact = parseCard(lines) {
                    contacts.append(contact)
                }
            } else if inCard {
                lines.append(trimmed)
            }
        }
        return contacts
    }

    /// Serialize contacts to vCard v3.0 format.
    public static func serialize(_ contacts: [Contact]) -> String {
        contacts.map(serializeOne).joined(separator: "\n")
    }

    // MARK: - Private

    private static func parseCard(_ lines: [String]) -> Contact? {
        var firstName = ""
        var lastName = ""
        var company = ""
        var email = ""
        var noblePubkey = ""
        var bitcoinKey = ""
        var notes = ""

        for line in lines {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let field = parts[0].uppercased()
            let value = String(parts[1])

            switch field {
            case "N":
                let nameParts = value.split(separator: ";", omittingEmptySubsequences: false)
                if nameParts.count >= 2 {
                    lastName = String(nameParts[0])
                    firstName = String(nameParts[1])
                }
            case "ORG":
                company = value
            case "EMAIL":
                email = value
            case "X-NOBLE-PUBKEY":
                noblePubkey = value
            case "X-NOBLE-BTCKEY":
                bitcoinKey = value
            case "NOTE":
                notes = value
            default:
                break
            }
        }

        return Contact(
            firstName: firstName,
            lastName: lastName,
            company: company,
            email: email,
            noblePubkey: noblePubkey,
            bitcoinKey: bitcoinKey,
            notes: notes
        )
    }

    private static func serializeOne(_ contact: Contact) -> String {
        var lines = [
            "BEGIN:VCARD",
            "VERSION:3.0",
            "N:\(contact.lastName);\(contact.firstName);;;",
            "FN:\(contact.displayName)",
        ]
        if !contact.company.isEmpty { lines.append("ORG:\(contact.company)") }
        if !contact.email.isEmpty { lines.append("EMAIL:\(contact.email)") }
        if !contact.noblePubkey.isEmpty { lines.append("X-NOBLE-PUBKEY:\(contact.noblePubkey)") }
        if !contact.bitcoinKey.isEmpty { lines.append("X-NOBLE-BTCKEY:\(contact.bitcoinKey)") }
        if !contact.notes.isEmpty { lines.append("NOTE:\(contact.notes)") }
        lines.append("END:VCARD")
        return lines.joined(separator: "\n")
    }
}
