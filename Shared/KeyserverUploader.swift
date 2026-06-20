import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp", category: "KeyserverUploader")

/// Publishes an armored public key to keys.openpgp.org via the Verifying
/// Keyserver (VKS) HTTP API and triggers UID verification mails.
///
/// VKS does not accept a key for public lookup until each UID has been
/// confirmed by the address holder clicking a verification link. The flow
/// is:
///
///   1. POST `/vks/v1/upload` with `{ "keytext": <armored-key> }`. The
///      reply lists every UID on the key with a per-UID `status` (pending
///      / published / revoked / unpublished).
///   2. POST `/vks/v1/request-verify` with `{ "token": <upload-token>,
///      "addresses": [<emails>] }` for any UID we want verification mails
///      sent to.
///   3. Each address holder receives a mail with a link; once clicked, the
///      key is publicly served at `/vks/v1/by-email/<addr>`.
///
/// Errors propagate as `KeyserverUploader.Error`. Network/TLS failures
/// arrive as `.networkError`; HTTP non-2xx as `.httpError`; malformed
/// reply bodies as `.malformedResponse`.
enum KeyserverUploader {
    static let host = "keys.openpgp.org"
    static let uploadPath = "/vks/v1/upload"
    static let verifyPath = "/vks/v1/request-verify"

    /// Server reply summarising the upload outcome. The verification step
    /// uses `token`; the UI shows `addresses` with the per-UID `status`.
    struct UploadResult: Equatable {
        let keyFingerprint: String
        let token: String
        /// Map of `email -> status` exactly as VKS returned it. Known
        /// statuses are `unpublished`, `pending`, `published`, `revoked`.
        let addressStatus: [String: String]
    }

    enum Error: Swift.Error, LocalizedError {
        case networkError(Swift.Error)
        case httpError(Int, body: String)
        case malformedResponse

        var errorDescription: String? {
            switch self {
            case let .networkError(inner): inner.localizedDescription
            case let .httpError(code, body):
                String(localized: "Keyserver upload failed (HTTP \(code)): \(body)")
            case .malformedResponse:
                String(localized: "Keyserver upload reply was not valid JSON.")
            }
        }
    }

    /// Uploads the armored key and returns the parsed VKS reply.
    static func upload(
        armoredKey: Data,
        session: URLSession = KeyserverSession.shared,
    ) async throws -> UploadResult {
        guard let armored = String(data: armoredKey, encoding: .utf8) else {
            throw Error.malformedResponse
        }
        let url = makeURL(path: uploadPath)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["keytext": armored])
        let (data, response) = try await postExpectingJSON(request: request, session: session)
        return try parseUploadReply(data: data, response: response)
    }

    /// Asks the VKS server to email verification links for the given
    /// addresses. The token comes from the prior `upload` call.
    static func requestVerify(
        token: String,
        addresses: [String],
        session: URLSession = KeyserverSession.shared,
    ) async throws {
        let url = makeURL(path: verifyPath)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(VKSVerifyRequest(token: token, addresses: addresses))
        _ = try await postExpectingJSON(request: request, session: session)
    }

    // MARK: – Private

    private static func makeURL(path: String) -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = path
        guard let url = components.url else {
            preconditionFailure("Failed to build VKS URL for \(path)")
        }
        return url
    }

    private static func postExpectingJSON(
        request: URLRequest,
        session: URLSession,
    ) async throws -> (Data, HTTPURLResponse) {
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            log.warning("VKS request failed: \(error.localizedDescription, privacy: .public)")
            throw Error.networkError(error)
        }
        guard let http = response as? HTTPURLResponse else {
            throw Error.malformedResponse
        }
        guard (200 ... 299).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw Error.httpError(http.statusCode, body: body)
        }
        return (data, http)
    }

    private static func parseUploadReply(
        data: Data,
        response: HTTPURLResponse,
    ) throws -> UploadResult {
        guard let parsed = try? JSONDecoder().decode(VKSUploadReply.self, from: data),
              let fpr = parsed.keyFingerprint,
              let token = parsed.token
        else {
            log.warning("VKS upload reply did not contain key_fpr+token (HTTP \(response.statusCode))")
            throw Error.malformedResponse
        }
        return UploadResult(
            keyFingerprint: fpr,
            token: token,
            addressStatus: parsed.status ?? [:],
        )
    }
}

private struct VKSUploadReply: Decodable {
    let keyFingerprint: String?
    let token: String?
    let status: [String: String]?

    enum CodingKeys: String, CodingKey {
        case keyFingerprint = "key_fpr"
        case token
        case status
    }
}

private struct VKSVerifyRequest: Encodable {
    let token: String
    let addresses: [String]
}
