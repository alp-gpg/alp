import Foundation
import Testing

@Suite("KeyserverRefreshService")
struct KeyserverRefreshServiceTests {
    final class StubFetcher: KeyserverFetcher, @unchecked Sendable {
        var stub: Result<FetchedKey, Error> = .success(.notPublished)
        func fetch(fingerprint _: String) async throws -> FetchedKey {
            try stub.get()
        }
    }

    final class StubImporter: KeyPreviewImporter, @unchecked Sendable {
        var previewResult: Result<[GPGKeyInfo], Error> = .success([])
        var importResult: Result<GPGImportResult, Error> = .success(
            GPGImportResult(fingerprint: nil, newKey: false, newUserIDs: false,
                            updatedSignatures: false, newSubkeys: false),
        )
        private(set) var importCalled = false
        func previewKey(_: Data) async throws -> [GPGKeyInfo] {
            try previewResult.get()
        }

        func importKey(_: Data) async throws -> GPGImportResult {
            importCalled = true
            return try importResult.get()
        }
    }

    private func expectedFingerprint() -> String {
        String(repeating: "A", count: 40)
    }

    @Test
    func `notPublished short-circuits before preview`() async throws {
        let fetcher = StubFetcher()
        fetcher.stub = .success(.notPublished)
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: expectedFingerprint())
        #expect(outcome == .notPublished)
        #expect(importer.importCalled == false)
    }

    @Test
    func `fingerprint mismatch throws and does NOT import`() async {
        let requested = expectedFingerprint()
        let other = String(repeating: "B", count: 40)
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: other, userIDs: [], capabilities: ""),
        ])
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: KeyserverRefreshError.self) {
            _ = try await service.refresh(fingerprint: requested)
        }
        #expect(importer.importCalled == false)
    }

    @Test
    func `updatedSignatures maps to .updated`() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: ""),
        ])
        importer.importResult = .success(
            GPGImportResult(fingerprint: fp, newKey: false, newUserIDs: false,
                            updatedSignatures: true, newSubkeys: false),
        )
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .updated)
        #expect(importer.importCalled == true)
    }

    @Test
    func `no changes maps to .alreadyCurrent`() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: ""),
        ])
        // All flags false — default importResult
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .alreadyCurrent)
    }

    @Test
    func `network error propagates`() async {
        let fetcher = StubFetcher()
        fetcher.stub = .failure(URLError(.notConnectedToInternet))
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: URLError.self) {
            _ = try await service.refresh(fingerprint: expectedFingerprint())
        }
    }
}
