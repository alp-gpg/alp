# Contributing to Alp

## Getting Started

1. Fork the repository and clone your fork.
2. Run `./scripts/setup.sh` — installs every Homebrew prerequisite and generates the Xcode project.
3. Create a branch for your change.

If you want to know exactly what Alp is doing before contributing, read [docs/VERIFYING.md](docs/VERIFYING.md). It maps each capability to the file that owns it.

## Development Workflow

```bash
tuist generate          # regenerate Xcode project after Project.swift changes
swiftlint               # lint
swiftformat .           # format
```

### Tests

```bash
bash scripts/test.sh    # what CI runs
```

`scripts/test.sh` builds, then runs `AlpTests` against a throwaway `$HOME`
holding a freshly generated fixture key, so the suite never touches — or
depends on — your own keyring. `⌘U` and a bare `xcodebuild test` still work but
run against your real keyring, so treat `scripts/test.sh` as the source of
truth. (gpg derives its homedir from `$HOME`; `GPGHelper.sanitizedEnvironment()`
strips `GNUPGHOME` on purpose, and that allowlist must not be relaxed for tests.)

`AlpXPCTests` is separate and opt-in. It talks to the **installed** helper over
a real `NSXPCConnection`, so it needs Alp.app installed with its helper
registered, and it is hosted inside Alp.app because `AlpHelper` rejects any
client that is not `app.alp.Alp`/`app.alp.Alp.extension`. Run it after a macOS
upgrade — it is the fastest check that launchd registration, the code-signing
requirement, and gpg detection all still work:

```bash
TEST_RUNNER_ALP_LIVE_XPC=1 xcodebuild test \
    -workspace Alp.xcworkspace -scheme AlpXPCTests -destination 'platform=macOS'
```

The `TEST_RUNNER_` prefix is required — `xcodebuild` strips it and forwards the
rest to the test process; without it the variable never reaches the suite and
every test skips. Without the variable set the suite skips entirely; with it,
an unreachable helper is a failure rather than a skip. One test briefly adds a
throwaway passphrase-less key to your real keyring (to exercise decrypt without
a pinentry prompt) and deletes it again afterwards.

## Code Style

- **SwiftLint** and **SwiftFormat** are configured via `.swiftlint.yml` and `.swiftformat`. CI enforces both.
- Swift 6.3 strict concurrency is enabled — all new code must be concurrency-safe.
- Keep `os_log` calls at default privacy. Never log plaintext, fingerprints, or email addresses.

## Architecture Notes

Understanding the target boundaries helps when deciding where code belongs:

| Target         | Sandbox | Can access                                         |
| -------------- | ------- | -------------------------------------------------- |
| `Alp`          | **No**  | SwiftUI, ServiceManagement, XPC to helper          |
| `AlpExtension` | Yes     | MailKit, SwiftUI, XPC to helper, HTTPS (keyserver) |
| `AlpHelper`    | **No**  | Foundation, Process (gpg binary), filesystem       |
| `AlpPinentry`  | **No**  | Cocoa (secure text field); runs under gpg-agent    |
| `Shared/`      | —       | Compiled into all targets above                    |

- Code that both the extension and helper need goes in `Shared/`.
- The extension **cannot** call `Process()` or access the filesystem — all gpg operations must go through the XPC helper.
- `Alp` is deliberately **not** sandboxed: since macOS 14.2 a sandboxed app can only register an SMAppService agent whose target executable is also sandboxed, and `AlpHelper` must stay unsandboxed to exec gpg. Sandboxing the app again breaks helper installation with `deny(1) job-creation` / "Operation not permitted". Keep gpg work in the helper anyway — the app talking to gpg directly is still a bug.
- MailKit protocol methods must be `nonisolated`. MailKit calls from its own XPC queue, not the main thread.

## Known Pitfalls

These are hard-won lessons. Please don't regress them:

- **`SMAppService.agent` not `.daemon`**: Daemons run as root and can't access `~/.gnupg`. The helper must be an agent.
- **AlpHelper code signing**: Requires `CREATE_INFOPLIST_SECTION_IN_BINARY`, `OTHER_CODE_SIGN_FLAGS --identifier`, hardened runtime, and Team ID. Without the embedded Info.plist, SMAppService rejects registration.
- **`gpg --batch` and decrypt**: `--batch` suppresses pinentry prompts. Never use it for decrypt operations.
- **Pipe deadlock**: stdout and stderr from gpg must be read concurrently. Sequential reads deadlock when either pipe's 64 KB buffer fills.
- **`gpg --verify` exit code**: Non-zero is valid (bad/untrusted signature). Parse status output regardless of exit code.

## Submitting Changes

1. Keep PRs focused — one logical change per PR.
2. Include a clear description of what changed and why.
3. Ensure CI passes (build, test, lint).
4. If you're adding a new GPG operation, add corresponding tests.
