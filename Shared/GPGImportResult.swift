import Foundation

/// Summary of a `gpg --import` run, parsed from the IMPORT_OK status line.
/// Bit mapping comes from gpg's `doc/DETAILS`:
///   1 = new key, 2 = new user IDs, 4 = new signatures, 8 = new subkeys.
struct GPGImportResult: Codable {
    let fingerprint: String?
    let newKey: Bool
    let newUserIDs: Bool
    let updatedSignatures: Bool
    let newSubkeys: Bool
}

extension GPGImportResult {
    /// Human-readable summary of the import outcome. Used for transient UI
    /// feedback after a successful import.
    var userFacingSummary: String {
        if newKey { return "Imported new key" }
        if updatedSignatures || newSubkeys || newUserIDs { return "Updated existing key" }
        return "Key already up to date"
    }
}
