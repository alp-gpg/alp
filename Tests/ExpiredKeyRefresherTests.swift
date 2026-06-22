import Foundation
import Testing

@Suite("ExpiredKeyRefresher")
@MainActor
struct ExpiredKeyRefresherTests {
    final class SlowStubImporter: KeyPreviewImporter, @unchecked Sendable {
        var delayNanos: UInt64 = 50_000_000
        let peak = AtomicCounter()
        func previewKey(_ data: Data) async throws -> [GPGKeyInfo] {
            let fp = String(data: data, encoding: .utf8) ?? ""
            return [GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: "")]
        }

        func importKey(_ data: Data) async throws -> GPGImportResult {
            await peak.enter()
            defer { Task { await peak.leave() } }
            try await Task.sleep(nanoseconds: delayNanos)
            let fp = String(data: data, encoding: .utf8)
            return GPGImportResult(
                fingerprint: fp,
                newKey: false,
                newUserIDs: false,
                updatedSignatures: true,
                newSubkeys: false,
            )
        }
    }

    final class StubFetcher: KeyserverFetcher, @unchecked Sendable {
        func fetch(fingerprint: String) async throws -> FetchedKey {
            .found(Data(fingerprint.utf8))
        }
    }

    private func makeKeys(count: Int) -> [GPGKeyInfo] {
        (0 ..< count).map { index in
            let fp = String(format: "%040d", index)
            return GPGKeyInfo(
                fingerprint: fp,
                userIDs: [],
                capabilities: "",
                expiryDate: Date(timeIntervalSince1970: 1),
            )
        }
    }

    @Test
    func `Parallelism is capped at 4`() async {
        let importer = SlowStubImporter()
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer,
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 4)
        let keys = makeKeys(count: 12)
        await refresher.runUntilDone(keys: keys)
        let peak = await importer.peak.peakValue
        #expect(peak <= 4, "Peak concurrency \(peak) exceeded cap 4")
    }

    @Test
    func `Cancellation stops further imports`() async {
        let importer = SlowStubImporter()
        importer.delayNanos = 200_000_000
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer,
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 2)
        let keys = makeKeys(count: 20)
        refresher.start(keys: keys)
        try? await Task.sleep(nanoseconds: 100_000_000)
        refresher.cancel()
        try? await Task.sleep(nanoseconds: 300_000_000)
        let completed = refresher.rowState.values.count(where: { state in
            if case .idle = state { return false }
            if case .fetching = state { return false }
            return true
        })
        #expect(completed < 20, "Expected cancellation to prevent finishing all 20 keys")
    }

    @Test
    func `Row states transition idle -> fetching -> updated`() async {
        let importer = SlowStubImporter()
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer,
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 4)
        let keys = makeKeys(count: 3)
        await refresher.runUntilDone(keys: keys)
        for key in keys {
            #expect(refresher.rowState[key.fingerprint] == .updated)
        }
    }
}

actor AtomicCounter {
    private var current = 0
    private(set) var peakValue = 0
    func enter() {
        current += 1
        if current > peakValue { peakValue = current }
    }

    func leave() {
        current -= 1
    }
}
