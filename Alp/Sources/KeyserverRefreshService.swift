import Foundation

/// Result of attempting to refresh a single key from keys.openpgp.org.
enum KeyserverRefreshOutcome: Equatable, Sendable {
    /// Upstream returned a newer self-signature or new subkey material;
    /// the local keyring has been updated.
    case updated
    /// Upstream has the key but it matches what we already have.
    case alreadyCurrent
    /// The key is not published on the keyserver.
    case notPublished
}

/// Errors specific to the keyserver refresh path. Generic network errors
/// bubble up as the underlying URLError / NSError from the URLSession call.
enum KeyserverRefreshError: Error, Equatable {
    /// The keyserver returned a key whose primary fingerprint does not match
    /// the one we requested. Treated as a *security* failure: the local
    /// keyring is never touched in this case.
    case fingerprintMismatch(requested: String, got: String?)
}

/// Network-facing seam for tests. Production uses `LiveKeyserverFetcher`
/// which wraps `KeyserverSession.shared`.
protocol KeyserverFetcher: Sendable {
    func fetch(fingerprint: String) async throws -> FetchedKey
}

enum FetchedKey: Sendable {
    case notPublished
    case found(Data)
}

/// Production fetcher against https://keys.openpgp.org over the pinned session.
struct LiveKeyserverFetcher: KeyserverFetcher {
    func fetch(fingerprint: String) async throws -> FetchedKey {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "keys.openpgp.org"
        components.percentEncodedPath = "/vks/v1/by-fingerprint/" + fingerprint
        guard let url = components.url, url.scheme == "https" else {
            throw KeyserverRefreshError.fingerprintMismatch(requested: fingerprint, got: nil)
        }
        let (data, response) = try await KeyserverSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse else { return .notPublished }
        switch http.statusCode {
        case 200: return .found(data)
        case 404: return .notPublished
        default:  throw URLError(.badServerResponse)
        }
    }
}

/// Thin wrapper over the helper's preview + import calls. A protocol so we
/// can inject a fake in unit tests without spinning up real gpg.
protocol KeyPreviewImporter: Sendable {
    func preview(_ data: Data) async throws -> [GPGKeyInfo]
    func `import`(_ data: Data) async throws -> GPGImportResult
}

struct LiveKeyPreviewImporter: KeyPreviewImporter {
    func preview(_ data: Data) async throws -> [GPGKeyInfo] {
        try await HelperXPCClient.shared.previewKey(data)
    }
    func `import`(_ data: Data) async throws -> GPGImportResult {
        try await HelperXPCClient.shared.importKey(data)
    }
}

/// Orchestrates: fetch → preview verify → import.
///
/// The preview step is the security guarantee: certificate pinning prevents
/// in-transit tampering, and fingerprint-matching catches the remaining case
/// where anything upstream returns an unexpected key.
struct KeyserverRefreshService: Sendable {
    let fetcher: KeyserverFetcher
    let importer: KeyPreviewImporter

    init(
        fetcher: KeyserverFetcher = LiveKeyserverFetcher(),
        importer: KeyPreviewImporter = LiveKeyPreviewImporter()
    ) {
        self.fetcher = fetcher
        self.importer = importer
    }

    func refresh(fingerprint expected: String) async throws -> KeyserverRefreshOutcome {
        let fetched = try await fetcher.fetch(fingerprint: expected)
        switch fetched {
        case .notPublished:
            return .notPublished
        case .found(let data):
            let previewed = try await importer.preview(data)
            guard previewed.first?.fingerprint == expected else {
                throw KeyserverRefreshError.fingerprintMismatch(
                    requested: expected,
                    got: previewed.first?.fingerprint
                )
            }
            let result = try await importer.import(data)
            if result.updatedSignatures || result.newSubkeys || result.newUserIDs {
                return .updated
            }
            return .alreadyCurrent
        }
    }
}
