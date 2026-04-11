import Foundation
import Testing

@Suite("KeyserverRefreshService")
struct KeyserverRefreshServiceTests {
    final class StubFetcher: KeyserverFetcher, @unchecked Sendable {
        var stub: Result<FetchedKey, Error> = .success(.notPublished)
        func fetch(fingerprint: String) async throws -> FetchedKey {
            try stub.get()
        }
    }

    final class StubImporter: KeyPreviewImporter, @unchecked Sendable {
        var previewResult: Result<[GPGKeyInfo], Error> = .success([])
        var importResult: Result<GPGImportResult, Error> = .success(
            GPGImportResult(fingerprint: nil, newKey: false, newUserIDs: false,
                            updatedSignatures: false, newSubkeys: false)
        )
        private(set) var importCalled = false
        func preview(_ data: Data) async throws -> [GPGKeyInfo] {
            try previewResult.get()
        }
        func `import`(_ data: Data) async throws -> GPGImportResult {
            importCalled = true
            return try importResult.get()
        }
    }

    private func expectedFingerprint() -> String { String(repeating: "A", count: 40) }

    @Test("notPublished short-circuits before preview")
    func notPublishedShortCircuits() async throws {
        let fetcher = StubFetcher()
        fetcher.stub = .success(.notPublished)
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: expectedFingerprint())
        #expect(outcome == .notPublished)
        #expect(importer.importCalled == false)
    }

    @Test("fingerprint mismatch throws and does NOT import")
    func fingerprintMismatchRejectsImport() async {
        let requested = expectedFingerprint()
        let other = String(repeating: "B", count: 40)
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: other, userIDs: [], capabilities: "")
        ])
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: KeyserverRefreshError.self) {
            _ = try await service.refresh(fingerprint: requested)
        }
        #expect(importer.importCalled == false)
    }

    @Test("updatedSignatures maps to .updated")
    func updatedSignaturesPath() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: "")
        ])
        importer.importResult = .success(
            GPGImportResult(fingerprint: fp, newKey: false, newUserIDs: false,
                            updatedSignatures: true, newSubkeys: false)
        )
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .updated)
        #expect(importer.importCalled == true)
    }

    @Test("no changes maps to .alreadyCurrent")
    func alreadyCurrentPath() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: "")
        ])
        // All flags false — default importResult
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .alreadyCurrent)
    }

    @Test("network error propagates")
    func networkErrorPropagates() async {
        let fetcher = StubFetcher()
        fetcher.stub = .failure(URLError(.notConnectedToInternet))
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: URLError.self) {
            _ = try await service.refresh(fingerprint: expectedFingerprint())
        }
    }
}
