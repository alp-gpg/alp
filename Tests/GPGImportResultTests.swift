import Foundation
import Testing

@Suite("GPGImportResult parsing")
struct GPGImportResultTests {
    @Test
    func `IMPORT_OK 0 → all flags false, fingerprint captured`() throws {
        let status = "[GNUPG:] IMPORT_OK 0 AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
        #expect(result.newKey == false)
        #expect(result.newUserIDs == false)
        #expect(result.updatedSignatures == false)
        #expect(result.newSubkeys == false)
    }

    @Test
    func `IMPORT_OK 1 → newKey`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 1 \(fp)"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.newKey == true)
        #expect(result.newUserIDs == false)
    }

    @Test
    func `IMPORT_OK 2 → newUserIDs`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 2 \(fp)"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.newUserIDs == true)
        #expect(result.newKey == false)
    }

    @Test
    func `IMPORT_OK 4 → updatedSignatures`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 4 \(fp)"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == false)
    }

    @Test
    func `IMPORT_OK 8 → newSubkeys`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 8 \(fp)"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.newSubkeys == true)
        #expect(result.updatedSignatures == false)
    }

    @Test
    func `IMPORT_OK 12 → updatedSignatures + newSubkeys (combined flags)`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 12 \(fp)"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == true)
        #expect(result.newUserIDs == false)
        #expect(result.newKey == false)
    }

    @Test
    func `Missing IMPORT_OK returns nil`() {
        let status = "[GNUPG:] IMPORT_PROBLEM 0"
        #expect(GPGHelper.parseImportResult(from: status) == nil)
    }

    @Test
    func `Multiple IMPORT_OK lines — returns the first one`() throws {
        let status = """
        [GNUPG:] IMPORT_OK 1 AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
        [GNUPG:] IMPORT_OK 4 BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666
        """
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
        #expect(result.newKey == true)
    }

    @Test
    func `IMPORT_OK embedded in realistic status stream`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = """
        [GNUPG:] KEY_CONSIDERED \(fp) 0
        [GNUPG:] IMPORT_OK 1 \(fp)
        [GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0
        """
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.newKey == true)
        #expect(result.fingerprint == fp)
    }

    @Test
    func `CRLF line endings are handled`() throws {
        let fp = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let status = "[GNUPG:] IMPORT_OK 1 \(fp)\r\n[GNUPG:] END\r\n"
        let result = try #require(GPGHelper.parseImportResult(from: status))
        #expect(result.fingerprint == fp, "Fingerprint should not be truncated by trailing \\r")
    }
}
