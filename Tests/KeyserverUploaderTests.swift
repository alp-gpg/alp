import Foundation
import Testing

@Suite("KeyserverUploader URL building")
struct KeyserverUploaderURLTests {
    /// The URL builder is private but the publicly observable host/path
    /// constants are what we want to verify.
    @Test
    func `host and paths match the VKS API spec`() {
        #expect(KeyserverUploader.host == "keys.openpgp.org")
        #expect(KeyserverUploader.uploadPath == "/vks/v1/upload")
        #expect(KeyserverUploader.verifyPath == "/vks/v1/request-verify")
    }
}

@Suite("KeyserverUploader error surface")
struct KeyserverUploaderErrorTests {
    @Test
    func `httpError carries status code and body in message`() {
        let err = KeyserverUploader.Error.httpError(429, body: "rate limited")
        let description = err.errorDescription ?? ""
        #expect(description.contains("429"))
        #expect(description.contains("rate limited"))
    }

    @Test
    func `malformedResponse has a non-empty description`() {
        let err = KeyserverUploader.Error.malformedResponse
        #expect(err.errorDescription?.isEmpty == false)
    }
}
