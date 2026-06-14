import CryptoKit
import Foundation
import Testing

@Suite("UpdateChecker")
@MainActor
struct UpdateCheckerTests {
    /// A throwaway Ed25519 keypair + a signed manifest for the happy path.
    private func signed(_ manifest: Data) -> (sig: String, pubB64: String, otherPubB64: String) {
        let key = Curve25519.Signing.PrivateKey()
        let sig = (try? key.signature(for: manifest)) ?? Data()
        let other = Curve25519.Signing.PrivateKey()
        return (
            sig.base64EncodedString(),
            key.publicKey.rawRepresentation.base64EncodedString(),
            other.publicKey.rawRepresentation.base64EncodedString(),
        )
    }

    private let manifest = Data(#"{"version":"1.2.0","minOS":"26.0","url":"https://example.com","sha256":"abc","notes":"hi"}"#
        .utf8)

    @Test
    func `valid signature verifies`() {
        let s = signed(manifest)
        #expect(UpdateChecker.verify(manifest: manifest, signatureBase64: s.sig, publicKeyBase64: s.pubB64))
    }

    @Test
    func `tampered manifest fails verification`() {
        let s = signed(manifest)
        let tampered = Data(#"{"version":"9.9.9","minOS":"26.0","url":"https://evil.com","sha256":"abc","notes":"hi"}"#
            .utf8)
        #expect(!UpdateChecker.verify(manifest: tampered, signatureBase64: s.sig, publicKeyBase64: s.pubB64))
    }

    @Test
    func `wrong key fails verification`() {
        let s = signed(manifest)
        #expect(!UpdateChecker.verify(manifest: manifest, signatureBase64: s.sig, publicKeyBase64: s.otherPubB64))
    }

    @Test
    func `truncated and garbage signatures fail`() {
        let s = signed(manifest)
        let truncated = String(s.sig.dropLast(8))
        #expect(!UpdateChecker.verify(manifest: manifest, signatureBase64: truncated, publicKeyBase64: s.pubB64))
        #expect(!UpdateChecker.verify(manifest: manifest, signatureBase64: "not base64!!", publicKeyBase64: s.pubB64))
        #expect(!UpdateChecker.verify(manifest: manifest, signatureBase64: "", publicKeyBase64: s.pubB64))
    }

    @Test
    func `version comparison incl downgrade and equality`() {
        #expect(UpdateChecker.isVersion("1.2.1", newerThan: "1.2.0"))
        #expect(UpdateChecker.isVersion("1.3.0", newerThan: "1.2.9"))
        #expect(UpdateChecker.isVersion("2.0.0", newerThan: "1.9.9"))
        #expect(UpdateChecker.isVersion("1.2.1", newerThan: "1.2"))
        #expect(!UpdateChecker.isVersion("1.2.0", newerThan: "1.2.0")) // equal → not newer
        #expect(!UpdateChecker.isVersion("1.2.0", newerThan: "1.2.1")) // downgrade
        #expect(!UpdateChecker.isVersion("1.2", newerThan: "1.2.0"))
    }

    @Test
    func `OS gate respects minimum`() {
        let os26 = OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0)
        let osLater = OperatingSystemVersion(majorVersion: 26, minorVersion: 2, patchVersion: 0)
        #expect(UpdateChecker.osMeets("26.0", current: os26))
        #expect(UpdateChecker.osMeets("26.0", current: osLater))
        #expect(!UpdateChecker.osMeets("26.3", current: osLater))
        #expect(!UpdateChecker.osMeets("27.0", current: osLater))
    }

    @Test
    func `decode rejects malformed JSON`() {
        #expect(UpdateChecker.decode(manifest) != nil)
        #expect(UpdateChecker.decode(Data("{not json".utf8)) == nil)
        #expect(UpdateChecker.decode(Data(#"{"version":"1.0"}"#.utf8)) == nil) // missing fields
    }

    private func checker(version: String, os: OperatingSystemVersion, pubKey: String) -> UpdateChecker {
        UpdateChecker(publicKeyBase64: pubKey, feedURL: nil, currentVersion: version, currentOS: os)
    }

    @Test
    func `evaluate offers a newer, OS-compatible release`() {
        let s = signed(manifest)
        let vm = checker(version: "1.1.0",
                         os: OperatingSystemVersion(majorVersion: 26, minorVersion: 1, patchVersion: 0),
                         pubKey: s.pubB64)
        guard case let .updateAvailable(release) = vm.evaluate(manifest: manifest, signatureBase64: s.sig) else {
            Issue.record("Expected updateAvailable")
            return
        }
        #expect(release.version == "1.2.0")
    }

    @Test
    func `evaluate reports up-to-date for same or older version`() {
        let s = signed(manifest)
        let vm = checker(version: "1.2.0",
                         os: OperatingSystemVersion(majorVersion: 26, minorVersion: 1, patchVersion: 0),
                         pubKey: s.pubB64)
        #expect(vm.evaluate(manifest: manifest, signatureBase64: s.sig) == .upToDate)
    }

    @Test
    func `evaluate fails closed on a bad signature`() {
        let s = signed(manifest)
        let vm = checker(version: "1.0.0",
                         os: OperatingSystemVersion(majorVersion: 26, minorVersion: 1, patchVersion: 0),
                         pubKey: s.otherPubB64) // wrong key
        guard case .failed = vm.evaluate(manifest: manifest, signatureBase64: s.sig) else {
            Issue.record("Expected failed for bad signature")
            return
        }
    }

    @Test
    func `evaluate suppresses a newer release that needs a newer macOS`() {
        let s = signed(manifest)
        let vm = checker(version: "1.0.0",
                         os: OperatingSystemVersion(majorVersion: 25, minorVersion: 0, patchVersion: 0),
                         pubKey: s.pubB64)
        #expect(vm.evaluate(manifest: manifest, signatureBase64: s.sig) == .upToDate)
    }
}
