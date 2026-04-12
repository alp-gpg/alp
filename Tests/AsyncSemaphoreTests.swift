import Foundation
import Testing

@Suite("AsyncSemaphore")
struct AsyncSemaphoreTests {
    @Test("Permits up to N concurrent holders, then gates")
    func concurrencyLimit() async {
        let sem = AsyncSemaphore(value: 2)
        let counter = ActorCounter()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 10 {
                group.addTask {
                    await sem.wait()
                    defer { Task { await sem.signal() } }
                    await counter.bump()
                    try? await Task.sleep(nanoseconds: 10_000_000)
                    await counter.dropAfter()
                }
            }
        }

        let peak = await counter.peak
        #expect(peak <= 2, "Peak concurrency \(peak) exceeded semaphore limit 2")
        #expect(peak >= 2, "Test didn't exercise contention — only \(peak) concurrent holders observed")
    }

    @Test("wait suspends when permits are zero and resumes on external signal")
    func suspendAndResume() async {
        let sem = AsyncSemaphore(value: 0)

        // Start a waiter that should suspend immediately.
        let waiterTask = Task {
            await sem.wait()
            return "resumed"
        }

        // Give the waiter a chance to actually enter the suspension.
        try? await Task.sleep(nanoseconds: 10_000_000)

        // Signal from outside — the suspended waiter should now resume.
        await sem.signal()

        let result = await waiterTask.value
        #expect(result == "resumed")
    }
}

private actor ActorCounter {
    private(set) var peak = 0
    private var current = 0
    func bump() {
        current += 1
        if current > peak { peak = current }
    }
    func dropAfter() { current -= 1 }
}
