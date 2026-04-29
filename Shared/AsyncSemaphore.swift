import Foundation

/// A minimal async-await counting semaphore. Used by `ExpiredKeyRefresher`
/// to cap parallel keyserver fetches.
///
/// The actor serializes access to `permits` and the waiter queue, and each
/// `wait()` suspends via a `CheckedContinuation` when no permit is free.
/// `signal()` resumes one waiter if any are queued, otherwise returns a
/// permit to the pool.
///
/// **Not cancellation-safe.** If a task is cancelled while suspended in
/// `wait()`, the continuation is leaked and the eventually-handed permit
/// is lost. Callers should check `Task.isCancelled` *between* semaphore
/// operations, not during a suspended `wait()`.
actor AsyncSemaphore {
    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(value: Int) {
        precondition(value >= 0, "AsyncSemaphore value must be non-negative")
        permits = value
    }

    func wait() async {
        if permits > 0 {
            permits -= 1
            return
        }
        await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }

    /// Resumes the first queued waiter (who now owns the permit the
    /// signaler released) or returns the permit to the pool if no waiter
    /// is queued. Must NOT increment `permits` when handing off — the
    /// waiter will consume the same permit that would otherwise have
    /// returned to the pool.
    func signal() {
        if let next = waiters.first {
            waiters.removeFirst()
            next.resume()
        } else {
            permits += 1
        }
    }
}
