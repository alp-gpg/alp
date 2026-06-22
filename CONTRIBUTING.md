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

Run tests before submitting (`⌘U` in Xcode or `xcodebuild test`).

## Code Style

- **SwiftLint** and **SwiftFormat** are configured via `.swiftlint.yml` and `.swiftformat`. CI enforces both.
- Swift 6.3 strict concurrency is enabled — all new code must be concurrency-safe.
- Keep `os_log` calls at default privacy. Never log plaintext, fingerprints, or email addresses.

## Architecture Notes

Understanding the target boundaries helps when deciding where code belongs:

| Target         | Sandbox | Can access                                         |
| -------------- | ------- | -------------------------------------------------- |
| `Alp`          | Yes     | SwiftUI, ServiceManagement, XPC to helper          |
| `AlpExtension` | Yes     | MailKit, SwiftUI, XPC to helper, HTTPS (keyserver) |
| `AlpHelper`    | **No**  | Foundation, Process (gpg binary), filesystem       |
| `Shared/`      | —       | Compiled into all targets above                    |

- Code that both the extension and helper need goes in `Shared/`.
- The extension **cannot** call `Process()` or access the filesystem — all gpg operations must go through the XPC helper.
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
