import Foundation

/// A minimal async-await counting semaphore. Used by `ExpiredKeyRefresher`
/// to cap parallel keyserver fetches.
///
/// The actor serializes access to `permits` and the waiter queue, and each
/// `wait()` suspends via a `CheckedContinuation` when no permit is free.
/// `signal()` resumes one waiter if any are queued, otherwise returns a
/// permit to the pool.
actor AsyncSemaphore {
    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(value: Int) {
        precondition(value >= 0, "AsyncSemaphore value must be non-negative")
        self.permits = value
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

    func signal() {
        if let next = waiters.first {
            waiters.removeFirst()
            next.resume()
        } else {
            permits += 1
        }
    }
}
