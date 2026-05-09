import Foundation

/// Subkey material attached to a primary key.
struct GPGSubkey: Codable, Identifiable, Hashable {
    let fingerprint: String
    /// gpg capability flags, e.g. "e", "s", "sca".
    let capabilities: String
    /// Unix-timestamped expiry, nil for non-expiring subkeys.
    let expiryDate: Date?
    /// Human-readable algorithm + size, e.g. "RSA 3072", "Ed25519". Nil when
    /// the listing didn't include enough information to format it.
    let algorithm: String?
    /// True when the subkey is revoked (`sub r:...` in colon output).
    let isRevoked: Bool

    var id: String {
        fingerprint
    }

    var isExpired: Bool {
        guard let expiryDate else { return false }
        return expiryDate < Date.now
    }

    /// SF Symbol names to render for each capability flag.
    var capabilityIcons: [String] {
        var icons: [String] = []
        let caps = capabilities.lowercased()
        if caps.contains("s") { icons.append("signature") }
        if caps.contains("e") { icons.append("lock") }
        if caps.contains("a") { icons.append("person.badge.key") }
        return icons
    }
}

/// A GPG primary key summary, JSON-serialisable for transport over XPC.
struct GPGKeyInfo: Codable, Identifiable, Hashable {
    let fingerprint: String
    let userIDs: [String]
    /// gpg capability flags for the primary key itself.
    let capabilities: String
    /// True when a matching secret key is available in the local keyring.
    var hasSecretKey: Bool
    /// Primary-key expiry, nil for non-expiring keys.
    var expiryDate: Date?
    /// Subkeys attached to this primary. Empty when the key has none.
    var subkeys: [GPGSubkey]
    /// Single-letter ownertrust value from `gpg --list-keys --with-colons`
    /// field 9 (one of `-`, `n`, `m`, `f`, `u`). nil when absent or not yet
    /// parsed. Use `OwnerTrust(rawValue:)` for a typed view.
    var ownerTrustCode: String?

    var id: String {
        fingerprint
    }

    var isExpired: Bool {
        guard let expiryDate else { return false }
        return expiryDate < Date.now
    }

    var displayName: String {
        userIDs.first ?? fingerprint
    }

    /// Lowercased addresses extracted from each UID's angle-bracketed
    /// `<email@host>` segment. UIDs without a bracketed address are skipped.
    var emails: [String] {
        userIDs.compactMap { uid in
            guard let lt = uid.firstIndex(of: "<"),
                  let gt = uid.lastIndex(of: ">"),
                  lt < gt else { return nil }
            let address = uid[uid.index(after: lt) ..< gt]
            return String(address).lowercased()
        }
    }

    /// Name-only portion of the primary UID, stripped of the email address.
    /// E.g. "Alice Example <alice@example.com>" → "Alice Example"
    var shortName: String {
        guard let uid = userIDs.first else { return String(fingerprint.prefix(8)) }
        if let range = uid.range(of: " <") {
            return String(uid[uid.startIndex ..< range.lowerBound])
        }
        return uid
    }

    /// Last 16 hex characters formatted as "ABCD 1234 EFGH 5678".
    var shortFingerprint: String {
        let last16 = String(fingerprint.suffix(16)).uppercased()
        guard last16.count == 16 else { return fingerprint }
        return stride(from: 0, to: 16, by: 4).map { i in
            let start = last16.index(last16.startIndex, offsetBy: i)
            let end = last16.index(start, offsetBy: 4)
            return String(last16[start ..< end])
        }.joined(separator: " ")
    }

    init(
        fingerprint: String,
        userIDs: [String],
        capabilities: String,
        hasSecretKey: Bool = false,
        expiryDate: Date? = nil,
        subkeys: [GPGSubkey] = [],
        ownerTrustCode: String? = nil,
    ) {
        self.fingerprint = fingerprint
        self.userIDs = userIDs
        self.capabilities = capabilities
        self.hasSecretKey = hasSecretKey
        self.expiryDate = expiryDate
        self.subkeys = subkeys
        self.ownerTrustCode = ownerTrustCode
    }
}

/// Typed view of the gpg ownertrust single-letter code. Maps the raw
/// character (field 9 of `pub` colon records) into a small set of
/// user-facing labels and colors.
enum OwnerTrust: Codable, Hashable {
    case unknown
    case never
    case marginal
    case full
    case ultimate

    init?(rawCode: String?) {
        switch rawCode {
        case "n": self = .never
        case "m": self = .marginal
        case "f": self = .full
        case "u": self = .ultimate
        case "-", "q", "o", nil: self = .unknown
        default: return nil
        }
    }

    var title: String {
        switch self {
        case .unknown: "Unknown"
        case .never: "Never"
        case .marginal: "Marginal"
        case .full: "Full"
        case .ultimate: "Ultimate"
        }
    }
}
