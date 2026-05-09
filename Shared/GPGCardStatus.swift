import Foundation

/// Read-only snapshot of an OpenPGP smartcard / YubiKey as reported by
/// `gpg --card-status --with-colons`. Returned as nil from the helper when
/// no card is currently inserted.
struct GPGCardStatus: Codable, Hashable {
    /// Manufacturer name decoded from the `vendor` line (e.g. "Yubico").
    let manufacturer: String?
    /// Hardware serial number (`serial` line).
    let serial: String?
    /// Cardholder name with gpg's `<<` first/last separator collapsed to
    /// a normal space (`name` line). Nil when the card has no cardholder.
    let cardholderName: String?
    /// On-card application version (e.g. "3.4") from the `version` line.
    let version: String?
    /// Remaining PIN attempts in the order [user PIN, reset code, admin PIN]
    /// as gpg reports on the `pinretry` line. Empty when not available.
    let pinRetriesLeft: [Int]
    /// Fingerprints of the on-card keys in slot order: [sign, encrypt, auth].
    /// Slots without a key contain an empty string.
    let keyFingerprints: [String]
    /// Algorithm description per slot (e.g. "RSA 4096", "Ed25519"). Same
    /// indexing as `keyFingerprints`.
    let keyAlgorithms: [String]

    /// True when the parser found at least one populated field — used as a
    /// "card is actually present" sentinel by the UI.
    var isPresent: Bool {
        manufacturer != nil || serial != nil || !pinRetriesLeft.isEmpty
    }
}
