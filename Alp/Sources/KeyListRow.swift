import SwiftUI

// swiftlint:disable identifier_name

/// Unified row type for the hierarchical Keys table.
enum KeyRow: Identifiable, Hashable {
    case primary(GPGKeyInfo)
    case subkey(GPGSubkey, parentFingerprint: String)

    var id: String {
        switch self {
        case .primary(let k):            return "p-\(k.fingerprint)"
        case .subkey(let s, let parent): return "s-\(parent)-\(s.fingerprint)"
        }
    }

    var displayName: String {
        switch self {
        case .primary(let k): return k.displayName
        case .subkey:         return ""
        }
    }

    var shortFingerprint: String {
        switch self {
        case .primary(let k):   return k.shortFingerprint
        case .subkey(let s, _): return Self.formatShortFP(s.fingerprint)
        }
    }

    var expiryDate: Date? {
        switch self {
        case .primary(let k):   return k.expiryDate
        case .subkey(let s, _): return s.expiryDate
        }
    }

    var isExpired: Bool {
        switch self {
        case .primary(let k):   return k.isExpired
        case .subkey(let s, _): return s.isExpired
        }
    }

    var isRevoked: Bool {
        switch self {
        case .primary:          return false
        case .subkey(let s, _): return s.isRevoked
        }
    }

    var capabilityIcons: [String] {
        switch self {
        case .primary(let k):   return Self.primaryIcons(from: k.capabilities)
        case .subkey(let s, _): return s.capabilityIcons
        }
    }

    var children: [KeyRow]? {
        switch self {
        case .primary(let k) where !k.subkeys.isEmpty:
            return k.subkeys.map { .subkey($0, parentFingerprint: k.fingerprint) }
        default:
            return nil
        }
    }

    // swiftlint:enable identifier_name

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
                let end   = last16.index(start, offsetBy: 4)
                return String(last16[start..<end])
            }
            .joined(separator: " ")
    }
}
