# Alp TODO

## Must Fix (manual release steps)

- [ ] Add GitHub secrets for release pipeline (`DEVELOPER_ID_CERTIFICATE_P12`,
      `DEVELOPER_ID_CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD`, `APPLE_ID`,
      `APPLE_ID_PASSWORD`, `APPLE_TEAM_ID`)
- [ ] Create `alp-gpg/homebrew-tap` repo with cask formula derived from
      `scripts/alp.rb.template`

## In Progress

- [ ] **Keys list hierarchy + expired key handling**
      Spec: `docs/superpowers/specs/2026-04-11-keys-list-hierarchy-design.md`

- [ ] **GPGTools-parity P0**
      Spec: `docs/superpowers/specs/2026-05-09-gpgtools-parity-design.md`
  - [ ] Helper RPCs: `deletePublicKey`, `deleteSecretKey`, `exportPublicKey`, `exportSecretKey`
  - [ ] Helper RPC: `generatePrimaryKey` (Ed25519 + Cv25519, 2y default expiry)
  - [ ] Helper RPCs: `changePassphrase`, `setExpiry`, `revokePrimaryKey`
  - [ ] Settings UI: per-row lifecycle actions + generate-key sheet
  - [ ] WKD lookup fallback (advanced + direct method)
  - [ ] First-run gpg install guidance in setup checklist
  - [ ] Pinentry-mac decision (bundle / brew / native)
  - [ ] Inline-PGP outgoing toggle for legacy recipients
  - [ ] Per-account default signing key (`from -> fingerprint` map)
  - [ ] Services menu target (Encrypt / Decrypt / Sign / Verify selection)
  - [ ] Sparkle auto-update wiring (EdDSA-signed appcast)

## Future / Deferred

Ideas captured while designing other work. Not scheduled — promote into a phase
when they become relevant. Each entry links to the spec it came from.

### From Keys UI hierarchy (2026-04-11)

- [ ] Key detail view (creation time, key flags, trust level, full fingerprint,
      per-subkey stats)
- [ ] "Cleanup" action — prune revoked/expired subkeys from the local keyring
- [ ] Per-subkey refresh from keyserver
- [ ] Tor / anonymity routing for keyserver fetches

*(WKD lookup and revocation certificate management promoted into the
GPGTools-parity P0 above.)*

### Unscheduled

- [ ] Helper crash notification with "reinstall" button
      (carried over from the original Phase 4 roadmap)

## Done

- ~~Security audit fixes~~ — 30 items across P0–P4, 62 tests green
- ~~Release pipeline~~ — `release.yml`, `build-release.sh`, `ExportOptions.plist`,
  `scripts/alp.rb.template`, SHA256SUMS generation
- ~~Setup checklist in GeneralSettingsView~~ — helper → GPG → Mail extension → signing key
- ~~Auto-navigate to problem area on launch~~ — `ContentView` jumps to Helper
  section when `helperStatus != .enabled`
- ~~Periodic health check~~ — `startPeriodicHealthCheck` while visible
- ~~Extension heartbeat via app group defaults~~
- ~~Compose session state tracking by `contextID`~~
- ~~"No GPG" indicator and encrypt tooltip in ComposeView~~
- ~~`canSign` / `canEncrypt` gating in ComposeViewModel~~
- ~~XPC reconnection + crash detection with 60s call timeout~~
- ~~Keyserver error differentiation (`.found`, `.notFound`, `.unreachable`)~~
- ~~Certificate pinning~~ — SPKI pinning, graceful fallback, UI warning, canary test
- ~~Human-readable GPG error mapping (`GPGError` cases, tests)~~
- ~~Key import from file in KeySettingsView~~
- ~~Expired key table badge + picker warning~~ *(finishing in the in-progress
  Keys UI hierarchy spec above)*
- ~~Test coverage~~ — 62 tests across 11 suites (parser, validation, tamper
  resistance, XPC roundtrip, keyserver pinning, compose session isolation,
  MIME edge cases)
- ~~Accessibility~~ — VoiceOver labels on all interactive elements
