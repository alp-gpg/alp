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

- **Mail just works.** Encrypted mail decrypts on read. Signed mail shows who signed it. Sign and encrypt with Mail's own compose controls; Alp's compose popover adds the signing-key picker, inline-PGP mode, and missing-key warnings with one-click import.
- **One-click key lookup.** Type a recipient who's not in your keyring and Alp finds them on `keys.openpgp.org` or via Web Key Directory.
- **Full key manager** in Settings → Keys. Generate, set expiry, change passphrase, back up, revoke, publish — without leaving the app.
- **Right-click on files** in Finder: Decrypt File, Verify File, Sign File, Encrypt File. Selected text gets Decrypt and Verify via the macOS Services menu (signing and encrypting need a recipient/key choice, so they stay file-only).
- **Encrypted backups.** "Back Up Key…" wraps your secret key, a fresh revocation cert, and ownertrust into one AES-256 file. "Restore Backup…" pulls it back on another Mac.

## Installation

Download the signed, notarized DMG from the [releases page](https://github.com/alp-gpg/alp/releases), open it, and drag Alp to Applications. To verify the download first, check it against the release's `SHA256SUMS` (GPG-signed — see [docs/VERIFYING.md](docs/VERIFYING.md)). Or build from source: [BUILDING.md](BUILDING.md).

You need macOS 26 (Tahoe) or later and GnuPG — the Setup checklist offers a one-click Homebrew install, or grab it from <https://gnupg.org/download/>. On first launch, **General → Setup** walks you through installing the background helper, checking GnuPG, enabling the Mail extension, and picking a default signing key.

Alp ships its own passphrase prompt — no `pinentry-mac` needed. Tap **General → Pinentry → "Use Alp Pinentry"** once and it's wired up. Prompted too often? That's gpg-agent's 10-minute idle cache, not Alp — Alp never stores your passphrase. Raise `default-cache-ttl 28800` / `max-cache-ttl 86400` (seconds) in `~/.gnupg/gpg-agent.conf`, then `gpgconf --reload gpg-agent`. The cache is memory-only; logout or reboot clears it.

## Privacy

- **No phone-home.** Zero analytics, zero crash reporting. A fresh install makes no network calls.
- **Updates are opt-in.** Flip the switch in General → Updates and Alp pulls security patches from `alp-gpg.github.io`. (Off by default; we still recommend turning it on so you don't miss fixes.)
- **Keyserver lookups happen only when you ask** — clicking _Find Key_, refreshing a key. Just typing a recipient does a local keyring lookup; no traffic.

## What encryption _doesn't_ protect

Alp warns you about both of these in-app too:

- **Drafts aren't encrypted.** Mail saves drafts to your IMAP/iCloud server while you type. For PGP accounts, turn off "Store drafts on server" in Mail → Settings → Accounts → Mailbox Behaviors.
- **Subject lines aren't encrypted.** Keep sensitive content in the body.

## Trust but verify

- [docs/VERIFYING.md](docs/VERIFYING.md) — signature checks, source-audit map, network proof, gpg-invocation reference.
- [docs/REPRODUCIBLE-BUILD.md](docs/REPRODUCIBLE-BUILD.md) — build from source, compare against the release.
- Every release ships SHA256SUMS for independent checksum verification.

## Contributing

Run `./scripts/setup.sh` to bootstrap the dev environment, then read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).
