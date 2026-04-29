import Foundation
import Observation

@MainActor
@Observable
final class ExpiredKeyRefresher {
    enum RowState: Equatable {
        case idle
        case fetching
        case updated
        case alreadyCurrent
        case notPublished
        case failed(String)
    }

    private(set) var rowState: [String: RowState] = [:]
    private(set) var isRunning = false

    private let service: KeyserverRefreshService
    private let maxConcurrent: Int
    private var currentTask: Task<Void, Never>?

    init(service: KeyserverRefreshService = KeyserverRefreshService(),
         maxConcurrent: Int = 4)
    {
        self.service = service
        self.maxConcurrent = maxConcurrent
    }

    func start(keys: [GPGKeyInfo]) {
        guard !isRunning else { return }
        isRunning = true
        for key in keys {
            rowState[key.fingerprint] = .idle
        }
        currentTask = Task { [weak self] in
            guard let self else { return }
            await run(keys: keys)
            await MainActor.run { self.isRunning = false }
        }
    }

    func cancel() {
        currentTask?.cancel()
    }

    func runUntilDone(keys: [GPGKeyInfo]) async {
        start(keys: keys)
        await currentTask?.value
    }

    private func run(keys: [GPGKeyInfo]) async {
        let semaphore = AsyncSemaphore(value: maxConcurrent)
        await withTaskGroup(of: Void.self) { group in
            for key in keys {
                let service = self.service
                let fp = key.fingerprint
                group.addTask { [weak self] in
                    await semaphore.wait()
                    defer { Task { await semaphore.signal() } }
                    guard !Task.isCancelled else { return }
                    await MainActor.run { self?.rowState[fp] = .fetching }
                    do {
                        let outcome = try await service.refresh(fingerprint: fp)
                        guard !Task.isCancelled else { return }
                        await MainActor.run { [outcome] in
                            switch outcome {
                            case .updated: self?.rowState[fp] = .updated
                            case .alreadyCurrent: self?.rowState[fp] = .alreadyCurrent
                            case .notPublished: self?.rowState[fp] = .notPublished
                            }
                        }
                    } catch {
                        let message = (error as? LocalizedError)?.errorDescription
                            ?? String(describing: error)
                        await MainActor.run { self?.rowState[fp] = .failed(message) }
                    }
                }
            }
        }
    }
}
