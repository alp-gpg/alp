# Release TODOs

## Must Fix (manual steps)

- Add GitHub secrets for release pipeline
- Create `alp-gpg/homebrew-tap` repo with cask formula from `scripts/alp.rb.template`

## UX Improvements (in progress)

### Phase 1: First-Time User Journey
- [ ] Setup checklist in GeneralSettingsView (helper → GPG → Mail extension → signing key)
- [ ] Auto-navigate to problem area on launch
- [ ] Extension heartbeat via app group defaults

### Phase 2: Compose Flow Correctness
- [ ] Sign defaults to OFF when no key configured
- [ ] Encrypt tooltip explaining why disabled
- [ ] Multiple compose window state fix (use contextID)
- [ ] "No GPG" indicator when both toggles off

### Phase 3: Error Message Quality
- [ ] Human-readable GPG error mapping
- [ ] XPC reconnection + crash detection
- [ ] Keyserver error differentiation

### Phase 4: Day-to-Day Polish
- [ ] Key import from file in KeySettingsView
- [ ] Expired key warnings (table badge + picker warning)
- [ ] Periodic health check (every 5 min while visible)
- [ ] Helper crash notification with reinstall button

## Done

- ~~Test coverage~~ — 40 tests across 7 suites
- ~~Release pipeline~~ — release.yml, build-release.sh, ExportOptions.plist, cask template
- ~~Accessibility~~ — VoiceOver labels on all interactive elements
- ~~Certificate pinning~~ — SPKI pinning with graceful fallback + UI warning + canary test
