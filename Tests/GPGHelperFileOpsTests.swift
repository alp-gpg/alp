import Foundation
import Testing

@Suite("GPGHelper file-op path validation")
struct GPGHelperFileOpsValidationTests {
    @Test
    func `isValidAbsolutePath accepts absolute paths`() {
        #expect(GPGHelper.isValidAbsolutePath("/tmp/file.gpg"))
        #expect(GPGHelper.isValidAbsolutePath("/Users/alice/Documents/secret"))
    }

    @Test
    func `isValidAbsolutePath rejects relative or empty paths`() {
        #expect(!GPGHelper.isValidAbsolutePath(""))
        #expect(!GPGHelper.isValidAbsolutePath("file.gpg"))
        #expect(!GPGHelper.isValidAbsolutePath("./file.gpg"))
        #expect(!GPGHelper.isValidAbsolutePath("../escape/file.gpg"))
    }

    @Test
    func `isValidAbsolutePath rejects embedded null bytes`() {
        #expect(!GPGHelper.isValidAbsolutePath("/tmp/file\0.gpg"))
    }

    @Test
    func `validateFileOpPaths rejects identical input + output`() throws {
        // Even if the file exists, refusing same-path keeps an accidental
        // helper invocation from silently clobbering the source.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("alp-fileops-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: url.path, contents: Data("payload".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(throws: GPGError.self) {
            try GPGHelper.validateFileOpPaths(
                inputPath: url.path,
                outputPath: url.path,
                requireInputExists: true,
            )
        }
    }

    @Test
    func `validateFileOpPaths rejects missing input when required`() {
        #expect(throws: GPGError.self) {
            try GPGHelper.validateFileOpPaths(
                inputPath: "/var/folders/this/does/not/exist/alp-nope",
                outputPath: "/tmp/alp-out.gpg",
                requireInputExists: true,
            )
        }
    }
}

@Suite("GPG file round-trip", .serialized)
struct GPGHelperFileRoundTripTests {
    let helper: GPGHelper
    let scratch: URL

    init() async throws {
        helper = await GPGHelper()
        scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("alp-fileops-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    private func cleanup() {
        try? FileManager.default.removeItem(at: scratch)
    }

    private func firstSecretKeyFingerprint() async throws -> String {
        let keys = try await helper._listSecretKeys()
        guard let fp = keys.first?.fingerprint else {
            Issue.record("No secret keys in keyring — skipping file-op tests")
            throw GPGError.noSigningKey
        }
        return fp
    }

    @Test
    func `Encrypt then decrypt a file on disk`() async throws {
        defer { cleanup() }
        let fp = try await firstSecretKeyFingerprint()
        let plaintextURL = scratch.appendingPathComponent("note.txt")
        let plaintext = Data("Streaming bytes through gpg\n".utf8)
        try plaintext.write(to: plaintextURL)

        let cipherURL = scratch.appendingPathComponent("note.txt.gpg")
        try await helper._encryptFile(
            inputPath: plaintextURL.path,
            outputPath: cipherURL.path,
            recipients: [fp],
            signer: fp,
        )
        #expect(FileManager.default.fileExists(atPath: cipherURL.path))

        let decryptedURL = scratch.appendingPathComponent("note.txt.decrypted")
        let (signer, _) = try await helper._decryptFile(
            inputPath: cipherURL.path,
            outputPath: decryptedURL.path,
        )
        #expect(signer != nil)

        let decrypted = try Data(contentsOf: decryptedURL)
        #expect(decrypted == plaintext)
    }

    @Test
    func `Detached sign then verify on disk`() async throws {
        defer { cleanup() }
        let fp = try await firstSecretKeyFingerprint()
        let dataURL = scratch.appendingPathComponent("doc.txt")
        try Data("doc body\n".utf8).write(to: dataURL)
        let sigURL = scratch.appendingPathComponent("doc.txt.sig")

        try await helper._signFile(
            inputPath: dataURL.path,
            outputPath: sigURL.path,
            signer: fp,
        )
        #expect(FileManager.default.fileExists(atPath: sigURL.path))

        let (valid, signer, _, _) = try await helper._verifyFile(
            inputPath: dataURL.path,
            signaturePath: sigURL.path,
        )
        #expect(valid)
        #expect(signer != nil)
    }

    @Test
    func `parseTrustLevel maps every TRUST_* tag`() {
        #expect(GPGHelper.parseTrustLevel(from: "[GNUPG:] TRUST_ULTIMATE\n") == "ultimate")
        #expect(GPGHelper.parseTrustLevel(from: "[GNUPG:] TRUST_FULLY 0\n") == "fully")
        #expect(GPGHelper.parseTrustLevel(from: "[GNUPG:] TRUST_MARGINAL\n") == "marginal")
        #expect(GPGHelper.parseTrustLevel(from: "[GNUPG:] TRUST_NEVER\n") == "never")
        #expect(GPGHelper.parseTrustLevel(from: "[GNUPG:] TRUST_UNDEFINED\n") == "undefined")
        #expect(GPGHelper.parseTrustLevel(from: "no trust line at all") == nil)
    }

    @Test
    func `Encrypt rejects bogus recipient fingerprint`() async throws {
        defer { cleanup() }
        let plaintextURL = scratch.appendingPathComponent("plain.txt")
        try Data("hi".utf8).write(to: plaintextURL)
        let cipherURL = scratch.appendingPathComponent("plain.txt.gpg")
        await #expect(throws: GPGError.self) {
            try await helper._encryptFile(
                inputPath: plaintextURL.path,
                outputPath: cipherURL.path,
                recipients: ["--homedir /tmp/evil"],
                signer: nil,
            )
        }
    }

    @Test
    func `Multi-file decrypt round-trip — independent inputs`() async throws {
        defer { cleanup() }
        let fp = try await firstSecretKeyFingerprint()
        let inputs = (0 ..< 3).map { idx in
            scratch.appendingPathComponent("note-\(idx).txt")
        }
        for (idx, url) in inputs.enumerated() {
            try Data("payload \(idx)".utf8).write(to: url)
        }
        // Mimic the multi-file batch driver: encrypt each file
        // independently, then decrypt each and confirm content survives.
        for input in inputs {
            let cipherURL = scratch.appendingPathComponent("\(input.lastPathComponent).gpg")
            try await helper._encryptFile(
                inputPath: input.path,
                outputPath: cipherURL.path,
                recipients: [fp],
                signer: nil,
            )
            let outURL = scratch.appendingPathComponent("\(input.lastPathComponent).out")
            _ = try await helper._decryptFile(
                inputPath: cipherURL.path,
                outputPath: outURL.path,
            )
            let original = try Data(contentsOf: input)
            let decrypted = try Data(contentsOf: outURL)
            #expect(decrypted == original)
        }
    }
}
