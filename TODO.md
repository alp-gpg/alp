# App Store Readiness TODOs

Remaining items that require architectural decisions or Apple engagement before the app
can pass Mac App Store review.

## Must Fix

### 1. Sandbox Temporary Exception for Mach Lookup
- `AlpExtension.entitlements` uses `com.apple.security.temporary-exception.mach-lookup.global-name`
- Apple discourages temporary sandbox exceptions for App Store apps
- **Action:** File a Technical Support Incident (TSI) with Apple to confirm the
  accepted XPC pattern for Mail extensions communicating with an unsandboxed helper.
  Alternatives: proper App Group XPC service, or `NSXPCConnection` via `SMAppService`
  without a Mach lookup exception.

### 2. External GPG Binary Dependency
- The app requires `brew install gnupg` — App Store apps should be self-contained
- The helper calls `/opt/homebrew/bin/gpg` (or other paths) via `Process()`
- **Action:** Either bundle a statically-linked gpg binary inside the app bundle, or
  replace with a Swift-native OpenPGP library (e.g. OpenPGP.swift, PGPy FFI, or a
  libgpgme xcframework). This is the largest architectural change required.

### 3. Bundle ID Prefix
- Bundle IDs default to `com.REPLACE_ME.alp` — set a proper reverse-domain prefix
  in `Project.swift` before release (e.g. `com.yourcompany`).
- All references are derived from the two variables at the top of `Project.swift`.

## Should Fix

### 4. Minimum Functionality — Host App
- The main app is only a settings window. Apple sometimes rejects apps where the host
  app has no standalone value (Guideline 4.0).
- **Action:** Consider adding an onboarding flow, key management features, or a
  status menu bar item to make the host app feel purposeful beyond extension settings.

### 5. Localization Completeness
- `Localizable.xcstrings` exists but verify all user-facing strings are covered,
  including error messages in `GPGError.swift` and the new
  `NSExtensionUsageDescription`.
- **Action:** Audit all user-facing strings and add localization keys.

### 6. Test Coverage
- Only 3 test files (~195 lines). Not an App Store requirement, but critical for
  stability before public release.
- **Action:** Add tests for `PGPMessageParser` edge cases, `ComposeViewModel` state
  transitions, `SecurityHandler` encode/decode paths, and XPC connection failure modes.

## Nice to Have

### 7. Certificate Pinning for Keyserver
- HTTPS calls to `keys.openpgp.org` have no certificate pinning.
- Low risk (ATS enforces TLS), but pinning adds defense-in-depth.

### 8. Accessibility Audit
- Verify VoiceOver labels on compose toolbar toggles, key table, and status badges.
- App Store reviewers occasionally test with VoiceOver.
