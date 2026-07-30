import Foundation
import Testing

// HelperConnection.call wraps *every* helper call, so a continuation bug here
// is a hung or crashed Mail process, not a localized failure. Swift traps hard
// on double-resuming a CheckedContinuation ("SWIFT TASK CONTINUATION MISUSE"),
// which means these tests completing at all is itself the proof that
// ResumeGuard admits exactly one claimant.
//
// No XPC traffic: `call` hands the body a proxy but sends nothing until a
// method is invoked on it, and none of these bodies touch it. That keeps the
// suite hermetic — it passes identically with or without a helper installed.

@Suite("HelperConnection resume guarding")
struct HelperConnectionResumeTests {
    @Test
    func `times out instead of leaking a continuation when the reply never comes`() async {
        // A crashed helper can drop a reply without firing the error handler.
        // Without the watchdog timer this await would never return.
        await #expect(throws: GPGError.self) {
            let _: Int = try await HelperConnection().call(timeout: 0.2) { _, _ in }
        }
    }

    @Test
    func `keeps the first result when the reply block fires repeatedly`() async throws {
        let value: Int = try await HelperConnection().call(timeout: 5) { _, resume in
            resume(.success(1))
            resume(.success(2))
            resume(.failure(GPGError.xpcUnavailable))
        }
        #expect(value == 1)
    }

    @Test
    func `admits exactly one claimant under concurrent resumes`() async throws {
        // The reply block is documented as safe to call from arbitrary XPC
        // queues, so the guard has to hold under a genuine race, not just
        // sequential re-entry.
        let value: Int = try await HelperConnection().call(timeout: 5) { _, resume in
            DispatchQueue.concurrentPerform(iterations: 64) { iteration in
                resume(.success(iteration))
            }
        }
        #expect((0 ..< 64).contains(value))
    }

    @Test
    func `ignores a reply that arrives after the timeout already fired`() async throws {
        // The dangerous ordering: watchdog resumes the continuation, then the
        // real reply turns up. The late resume must be dropped, not trapped on.
        await #expect(throws: GPGError.self) {
            let _: Int = try await HelperConnection().call(timeout: 0.2) { _, resume in
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.6) {
                    resume(.success(7))
                }
            }
        }
        // Outlive the late resume — the crash it would cause happens off this
        // task, so returning before it fires would report a false pass.
        try await Task.sleep(for: .seconds(1))
    }
}
