<p align="center">
  <img src="Alp/Resources/Logo/alp-logo.svg" alt="Alp" width="180" />
</p>

<h1 align="center">Alp</h1>

<p align="center">GPG for Apple Mail on macOS 26+.</p>

<p align="center">
  <a href="https://github.com/alp-gpg/alp/actions/workflows/ci.yml"><img src="https://github.com/alp-gpg/alp/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/alp-gpg/alp/releases"><img src="https://img.shields.io/github/v/release/alp-gpg/alp?include_prereleases&label=release" alt="Latest release" /></a>
  <a href="https://github.com/alp-gpg/alp/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg" alt="License: GPL-3.0-or-later" /></a>
</p>

---

> [!WARNING]
> **Alp is beta software (pre-1.0).** It's feature-complete but hasn't been field-tested at scale, and it handles your private keys and passphrases. Keep independent backups of your keys, expect rough edges, and report anything that looks wrong at [github.com/alp-gpg/alp/issues](https://github.com/alp-gpg/alp/issues).

Sign, encrypt, decrypt, and verify mail in Apple Mail using your existing GnuPG keys. Alp doesn't replace Mail and doesn't store your keys — `gpg-agent` keeps doing that.

## What you get

- **Mail integration.** Encrypted mail decrypts on read. Signed mail shows who signed it. Sign and encrypt with Mail's own compose controls; Alp's compose popover adds the signing-key picker, inline-PGP mode, and missing-key warnings with one-click import.
- **Key lookup.** For a recipient missing from your keyring, _Find Key_ searches `keys.openpgp.org`, the recipient's Web Key Directory, `api.protonmail.ch`, and `keyserver.ubuntu.com`.
- **Full key manager** in Settings → Keys. Generate, set expiry, change passphrase, back up, revoke, publish — without leaving the app.
- **Finder and Services menu.** Files: Decrypt / Verify / Sign / Encrypt File with Alp. Selected text: Decrypt with Alp, Verify with Alp (signing and encrypting need a key choice, so they are file-only).
- **Encrypted backups.** "Back Up Key…" writes your secret key, a fresh revocation certificate, and ownertrust into one passphrase-encrypted file (AES-256, OCB AEAD on gpg ≥ 2.3). "Restore Backup" imports it on another Mac.

## Installation

Download the signed, notarized DMG from the [releases page](https://github.com/alp-gpg/alp/releases), open it, and drag Alp to Applications. To verify the download first, check it against the release's `SHA256SUMS` (GPG-signed — see [docs/VERIFYING.md](docs/VERIFYING.md)). Or build from source: [BUILDING.md](BUILDING.md).

You need macOS 26 (Tahoe) or later (tested on macOS 27) and GnuPG (`brew install gnupg`, or the installer from <https://gnupg.org/download/>). On first launch, **General → Setup** walks you through installing the helper (`AlpHelper`, a launch agent registered via SMAppService), checking GnuPG, enabling the Mail extension, and picking a default signing key.

Alp includes its own pinentry, so `pinentry-mac` is not needed. Enable it in **General → Pinentry → "Use Alp Pinentry"**. Alp never stores passphrases; gpg-agent caches them in memory for 10 minutes by default. To lengthen that, set `default-cache-ttl` / `max-cache-ttl` (seconds) in `~/.gnupg/gpg-agent.conf` and run `gpgconf --reload gpg-agent`. Logout or reboot clears the cache.

## Privacy

- **No analytics or crash reporting.** A fresh install makes no network connections.
- **Update checks are opt-in** (General → Updates, off by default). When enabled, Alp fetches a signed `release.json` from `alp-gpg.github.io/alp/` and tells you when a newer DMG exists. It never downloads or installs anything.
- **Keyserver traffic only on explicit action:** _Find Key_, refreshing or publishing a key, or the opt-in publish-status check (General → Keyserver Security). Typing a recipient searches the local keyring only.

## What encryption _doesn't_ protect

Alp warns you about both of these in-app too:

- **Drafts aren't encrypted.** Mail saves drafts to your IMAP/iCloud server while you type. For PGP accounts, turn off "Store drafts on server" in Mail → Settings → Accounts → Mailbox Behaviors.
- **Subject lines aren't encrypted.** Keep sensitive content in the body.

## Trust but verify

- [docs/VERIFYING.md](docs/VERIFYING.md) — signature checks, source-audit map, network proof, gpg-invocation reference.
- [docs/REPRODUCIBLE-BUILD.md](docs/REPRODUCIBLE-BUILD.md) — build from source, compare against the release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).
