import Foundation

/// A GPG key summary, JSON-serialisable for transport over XPC.
struct GPGKeyInfo: Codable, Sendable, Identifiable {
    let fingerprint: String
    let userIDs: [String]
    /// Capability flags from gpg --with-colons: e.g. "scESC"
    let capabilities: String
    /// True when a matching secret key is available in the local keyring.
    var hasSecretKey: Bool
    /// Expiry date of the primary key, or nil if the key never expires.
    var expiryDate: Date?

    var id: String { fingerprint }

    /// The primary UID display string (first UID, or fingerprint if empty).
    var displayName: String { userIDs.first ?? fingerprint }

    /// Name-only portion of the primary UID, stripped of the email address.
    /// E.g. "Alice Example <alice@example.com>" → "Alice Example"
    var shortName: String {
        guard let uid = userIDs.first else { return String(fingerprint.prefix(8)) }
        if let range = uid.range(of: " <") {
            return String(uid[uid.startIndex..<range.lowerBound])
        }
        return uid
    }

    /// Last 16 hex characters formatted as "ABCD 1234 EFGH 5678".
    var shortFingerprint: String {
        let last16 = String(fingerprint.suffix(16)).uppercased()
        guard last16.count == 16 else { return fingerprint }
        return stride(from: 0, to: 16, by: 4).map { i in
            let start = last16.index(last16.startIndex, offsetBy: i)
            let end   = last16.index(start, offsetBy: 4)
            return String(last16[start..<end])
        }.joined(separator: " ")
    }

    // Custom Codable so hasSecretKey defaults to false when absent (e.g. old XPC responses).
    init(fingerprint: String, userIDs: [String], capabilities: String, hasSecretKey: Bool = false, expiryDate: Date? = nil) {
        self.fingerprint = fingerprint
        self.userIDs = userIDs
        self.capabilities = capabilities
        self.hasSecretKey = hasSecretKey
        self.expiryDate = expiryDate
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        fingerprint  = try c.decode(String.self,   forKey: .fingerprint)
        userIDs      = try c.decode([String].self, forKey: .userIDs)
        capabilities = try c.decode(String.self,   forKey: .capabilities)
        hasSecretKey = try c.decodeIfPresent(Bool.self, forKey: .hasSecretKey) ?? false
        expiryDate   = try c.decodeIfPresent(Date.self, forKey: .expiryDate)
    }
}
