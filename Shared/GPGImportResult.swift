import Foundation

/// Summary of a `gpg --import` run, parsed from the IMPORT_OK status line.
/// Bit mapping comes from gpg's `doc/DETAILS`:
///   1 = new key, 2 = new user IDs, 4 = new signatures, 8 = new subkeys.
struct GPGImportResult: Codable, Sendable {
    let fingerprint: String?
    let newKey: Bool
    let newUserIDs: Bool
    let updatedSignatures: Bool
    let newSubkeys: Bool
}
