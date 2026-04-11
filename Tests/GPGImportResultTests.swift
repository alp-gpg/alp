import Foundation
import Testing

@Suite("GPGImportResult parsing")
struct GPGImportResultTests {
    @Test("IMPORT_OK 0 → all flags false, fingerprint captured")
    func notActuallyChanged() {
        let status = "[GNUPG:] IMPORT_OK 0 AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
        #expect(result.newKey == false)
        #expect(result.newUserIDs == false)
        #expect(result.updatedSignatures == false)
        #expect(result.newSubkeys == false)
    }

    @Test("IMPORT_OK 1 → newKey")
    func entirelyNewKey() {
        let status = "[GNUPG:] IMPORT_OK 1 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newKey == true)
        #expect(result.newUserIDs == false)
    }

    @Test("IMPORT_OK 2 → newUserIDs")
    func newUserIDs() {
        let status = "[GNUPG:] IMPORT_OK 2 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newUserIDs == true)
        #expect(result.newKey == false)
    }

    @Test("IMPORT_OK 4 → updatedSignatures")
    func newSignatures() {
        let status = "[GNUPG:] IMPORT_OK 4 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == false)
    }

    @Test("IMPORT_OK 8 → newSubkeys")
    func newSubkeys() {
        let status = "[GNUPG:] IMPORT_OK 8 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newSubkeys == true)
        #expect(result.updatedSignatures == false)
    }

    @Test("IMPORT_OK 12 → updatedSignatures + newSubkeys (combined flags)")
    func combinedFlags() {
        let status = "[GNUPG:] IMPORT_OK 12 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == true)
        #expect(result.newUserIDs == false)
        #expect(result.newKey == false)
    }

    @Test("Missing IMPORT_OK returns nil fingerprint and all flags false")
    func missingLine() {
        let status = "[GNUPG:] IMPORT_PROBLEM 0"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.fingerprint == nil)
        #expect(result.newKey == false)
    }
}
