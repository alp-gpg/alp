# Reproducible Builds

Alp aims for builds that anyone with the same tag, Xcode version, and
toolchain produces a binary that runs identically to the released DMG.
Bit-for-bit reproducibility on Apple platforms is partially out of our
hands (signed timestamps, provisioning profiles, build UUIDs change
between machines), so this document is honest about what _is_ and what
_is not_ reproducible.

## What is reproducible

These pieces of the build are byte-identical across machines when the
inputs match:

- **Source compilation.** Swift 6.3 with `-strict-concurrency=complete`
  and the project-pinned settings produces deterministic object code.
- **Tuist project generation.** `tuist generate` is deterministic given
  the same `Project.swift`.
- **Dependency versions.** None — Alp has **zero** third-party Swift
  package dependencies. Updates are handled by the in-house, notification-only
  `UpdateChecker` (CryptoKit), not Sparkle.
- **Assets and Info.plist.** Captured by Tuist; no per-machine variance.

## What is not reproducible (and why)

- **Code signature.** Each build is signed with the operator's
  Developer ID certificate. Two operators using different certs will
  produce different signatures.
- **Notarization stapling.** The notary service issues a per-submission
  ticket. Different submissions of the same binary produce different
  stapled tickets.
- **Build UUID** (`LC_UUID` Mach-O load command). Generated per link;
  no stable input.
- **`DT_*` keys in Info.plist** that record Xcode build numbers.

For the released DMG these last items are baked in by the release
machine. They do not affect runtime behavior or expose any secret —
they are bookkeeping the OS uses.

## Reproducing a release locally

```bash
git fetch --tags
git checkout v<VERSION>
./scripts/setup.sh
tuist generate
xcodebuild build \
    -workspace Alp.xcworkspace \
    -scheme Alp \
    -configuration Release \
    -destination 'platform=macOS' \
    CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO
```

`CODE_SIGN_IDENTITY="-"` builds an ad-hoc–signed binary so the
signature you get is independent of any Developer ID. You can then:

1. Run the resulting `Alp.app` and confirm it behaves identically to
   the released DMG.
2. Compare the Swift source files of the running app's `.dylib` against
   the source you built — they should match line-for-line in symbols.
3. Inspect the gpg invocations the helper makes (every one is
   constructed in `AlpHelper/Sources/GPGHelper.swift` and
   `AlpHelper/Sources/GPGHelper+FileOps.swift`).

## Verifying a released DMG against the source

```bash
# 1. Confirm the DMG is signed by the published Team ID
codesign -dvv /Volumes/Alp/Alp.app 2>&1 | grep TeamIdentifier
# Expect: TeamIdentifier=3G6WR6H4M5

# 2. Confirm Apple notarized it
spctl --assess --type execute --verbose /Volumes/Alp/Alp.app
# Expect: accepted, source=Notarized Developer ID

# 3. Build from the matching git tag (see above) and run side by side.
# Any behavioral divergence is a finding — please file an issue.
```

## Future work

We would like to publish a SLSA build provenance attestation for each
release so a third party can verify, from a GitHub Actions log alone,
that the published DMG came from a specific commit. That is on the
roadmap but not yet implemented.

Until then, the recipe above is the best we offer: build it yourself,
or read the source and trust your own audit.
