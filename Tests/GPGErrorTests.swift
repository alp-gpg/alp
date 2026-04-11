import Foundation
import Testing

struct GPGErrorTests {
    @Test
    func `Each case has a localized description`() throws {
        let cases: [GPGError] = [
            .gpgNotFound,
            .processError(exitCode: 2, stderr: "fail"),
            .noSigningKey,
            .missingKeys(["a@b.com", "c@d.com"]),
            .decryptionFailed("bad"),
            .verificationFailed("untrusted"),
            .xpcUnavailable,
            .encodingError("nil data"),
            .importRejected("bad key material"),
        ]
        for error in cases {
            #expect(error.errorDescription != nil)
            #expect(try !(#require(error.errorDescription?.isEmpty)))
        }
    }

    @Test
    func `importRejected has a localized description`() {
        let err = GPGError.importRejected("bad key material")
        #expect(err.errorDescription?.isEmpty == false)
        #expect(err.errorDescription?.contains("bad key material") == true)
    }

    @Test
    func `gpgNotFound mentions brew install`() throws {
        #expect(try #require(GPGError.gpgNotFound.errorDescription?.contains("brew install")))
    }

    @Test
    func `missingKeys lists emails`() throws {
        let error = GPGError.missingKeys(["alice@test.com", "bob@test.com"])
        #expect(try #require(error.errorDescription?.contains("alice@test.com")))
        #expect(try #require(error.errorDescription?.contains("bob@test.com")))
    }

    @Test
    func `xpcUnavailable mentions helper`() throws {
        #expect(try #require(GPGError.xpcUnavailable.errorDescription?.contains("helper")))
    }

    @Test
    func `asNSError preserves domain and description`() {
        let error = GPGError.noSigningKey
        let ns = error.asNSError
        #expect(ns.domain == "app.alp.Alp.GPGError")
        #expect(ns.code == 3)
        #expect(ns.localizedDescription.contains("signing"))
    }

    @Test
    func `Each case maps to a unique NSError code`() {
        let cases: [GPGError] = [
            .gpgNotFound, .processError(exitCode: 0, stderr: ""),
            .noSigningKey, .missingKeys([]), .decryptionFailed(""),
            .verificationFailed(""), .xpcUnavailable, .encodingError(""),
            .importRejected(""),
        ]
        let codes = cases.map(\.asNSError.code)
        #expect(Set(codes).count == codes.count)
    }
}
