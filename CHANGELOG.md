# Changelog

Feeds the `notes` field of the update manifest: at release time, condense the
Unreleased section into `RELEASE_NOTES` for `scripts/build-release.sh`, then
move the entries under the new version heading.

## Unreleased

- **Fixed: key backup never worked.** Creating a backup failed outright on
  gpg ≥ 2.3 (an invalid `--aead` flag — all Homebrew installs are affected),
  and restoring a bundle imported its embedded revocation certificate, so a
  restored key came back revoked. Backups now encrypt with OCB AEAD
  (`--force-ocb`), and the revocation certificate carries gpg's own
  colon guard so a restore can never revoke the key it brings back.
- **Fixed: revoking a key without a description silently failed.** The gpg
  transcript answered the final confirmation with a stray blank line; gpg
  aborted and the key stayed unrevoked while the UI showed an opaque error.

## 0.9.4

- Fixes a race that left the Keys tab stuck on "Couldn't Load Keys" right
  after installing the helper, and surfaces a registered-but-unresponsive
  helper in Settings with recovery steps (Login Items, reinstall, reboot).
