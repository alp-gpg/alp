# Alp TODO

## Operator (manual, blocking first public release)

- [ ] Add GitHub secrets for the release pipeline:
      `DEVELOPER_ID_CERTIFICATE_P12`, `DEVELOPER_ID_CERTIFICATE_PASSWORD`,
      `KEYCHAIN_PASSWORD`, `APPLE_ID`, `APPLE_ID_PASSWORD`, `APPLE_TEAM_ID`.
- [ ] Create `alp-gpg/homebrew-tap` repo with a cask formula derived
      from `scripts/alp.rb.template`.
- [ ] Enable GitHub Pages on `alp-gpg/alp` from `/docs` once the repo is
      public, so the Sparkle appcast is served at
      <https://alp-gpg.github.io/alp/appcast.xml>.

## Future ideas (not scheduled)

- [ ] Per-subkey refresh from keyserver (today's refresh is whole-primary).
- [ ] Tor / SOCKS proxy for keyserver fetches.
- [ ] Real translations once a native speaker is available per locale —
      the xcstrings catalog already captures every user-facing string.
- [ ] File encryption / decryption (Services menu currently text-only).
- [ ] Address-book "encryptable" badge in Contacts.
