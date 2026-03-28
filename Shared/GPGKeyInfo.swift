import Foundation

/// A GPG key summary, JSON-serialisable for transport over XPC.
struct GPGKeyInfo: Codable, Sendable, Identifiable {
    let fingerprint: String
    let userIDs: [String]
    /// Capability flags from gpg --with-colons: e.g. "scESC"
    let capabilities: String

    var id: String { fingerprint }

    /// The primary UID display string (first UID, or fingerprint if empty).
    var displayName: String { userIDs.first ?? fingerprint }
}
