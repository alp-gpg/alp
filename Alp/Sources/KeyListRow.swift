import SwiftUI

/// Unified row type for the hierarchical Keys table.
enum KeyRow: Identifiable, Hashable {
    case primary(GPGKeyInfo)
    case subkey(GPGSubkey, parentFingerprint: String)

    var id: String {
        switch self {
        case let .primary(k): "p-\(k.fingerprint)"
        case let .subkey(s, parent): "s-\(parent)-\(s.fingerprint)"
        }
    }

    var displayName: String {
        switch self {
        case let .primary(k): k.displayName
        case .subkey: ""
        }
    }

    var shortFingerprint: String {
        switch self {
        case let .primary(k): k.shortFingerprint
        case let .subkey(s, _): Self.formatShortFP(s.fingerprint)
        }
    }

    var expiryDate: Date? {
        switch self {
        case let .primary(k): k.expiryDate
        case let .subkey(s, _): s.expiryDate
        }
    }

    var isExpired: Bool {
        switch self {
        case let .primary(k): k.isExpired
        case let .subkey(s, _): s.isExpired
        }
    }

    var isRevoked: Bool {
        switch self {
        case .primary: false
        case let .subkey(s, _): s.isRevoked
        }
    }

    var capabilityIcons: [String] {
        switch self {
        case let .primary(k): Self.primaryIcons(from: k.capabilities)
        case let .subkey(s, _): s.capabilityIcons
        }
    }

    var children: [KeyRow]? {
        switch self {
        case let .primary(k) where !k.subkeys.isEmpty:
            k.subkeys.map { .subkey($0, parentFingerprint: k.fingerprint) }
        default:
            nil
        }
    }

    private static func primaryIcons(from capabilities: String) -> [String] {
        var icons: [String] = []
        let caps = capabilities.lowercased()
        if caps.contains("s") { icons.append("signature") }
        if caps.contains("e") { icons.append("lock") }
        if caps.contains("a") { icons.append("person.badge.key") }
        if caps.contains("c") { icons.append("checkmark.seal") }
        return icons
    }

    private static func formatShortFP(_ fingerprint: String) -> String {
        let last16 = String(fingerprint.suffix(16)).uppercased()
        guard last16.count == 16 else { return fingerprint }
        return stride(from: 0, to: 16, by: 4)
            .map { offset in
                let start = last16.index(last16.startIndex, offsetBy: offset)
                let end = last16.index(start, offsetBy: 4)
                return String(last16[start ..< end])
            }
            .joined(separator: " ")
    }
}
