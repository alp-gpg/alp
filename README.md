<p align="center">
  <img src="Alp/Resources/Logo/alp-logo.svg" alt="Alp" width="180" />
</p>

<h1 align="center">Alp</h1>

<p align="center">GPG for Apple Mail on macOS 26.</p>

---

Sign, encrypt, decrypt, and verify mail in Apple Mail using your existing GnuPG keys. Alp doesn't replace Mail and doesn't store your keys — `gpg-agent` keeps doing that.

## What you get

- **Mail just works.** Encrypted mail decrypts on read. Signed mail shows who signed it. The compose window grows a Sign / Encrypt / Inline toggle.
- **One-click key lookup.** Type a recipient who's not in your keyring and Alp finds them on `keys.openpgp.org` or via Web Key Directory.
- **Full key manager** in Settings → Keys. Generate, set expiry, change passphrase, back up, revoke, publish — without leaving the app.
- **Right-click on files** in Finder: Decrypt File, Verify File, Sign File, Encrypt File. Same for selected text via the macOS Services menu.
- **Encrypted backups.** "Back Up Key…" wraps your secret key, a fresh revocation cert, and ownertrust into one AES-256 file. "Restore Backup…" pulls it back on another Mac.

## Installation

Pre-built binaries aren't published yet — see [BUILDING.md](BUILDING.md) to build from source.

On first launch, **General → Setup** walks you through four steps: install the background helper, check your GnuPG install, enable the Mail extension in System Settings, and pick a default signing key. Each step has a button.

You need macOS 26 (Tahoe) and GnuPG. The Setup checklist offers a one-click Homebrew install; if you'd rather, grab GnuPG from <https://gnupg.org/download/>.

Alp ships its own passphrase prompt — no `pinentry-mac` install required. Tap **General → Pinentry → "Use Alp Pinentry"** once and it's wired up.

## Privacy

- **No phone-home.** Zero analytics, zero crash reporting. A fresh install makes no network calls.
- **Updates are opt-in.** Flip the switch in General → Updates and Alp pulls security patches from `alp-gpg.github.io`. (Off by default; we still recommend turning it on so you don't miss fixes.)
- **Keyserver lookups happen only when you ask** — clicking *Find Key*, refreshing a key. Just typing a recipient does a local keyring lookup; no traffic.

## What encryption *doesn't* protect

Two limits worth knowing about PGP-on-Mail. Alp also warns you about these inside the app:

- **Drafts aren't encrypted.** Mail saves drafts to your IMAP/iCloud server while you type. For PGP accounts, turn off "Store drafts on server" in Mail → Settings → Accounts → Mailbox Behaviors.
- **Subject lines aren't encrypted.** Keep sensitive content in the body.

## Trust but verify

We try to be transparent. If you want to confirm Alp does what it says:

- [docs/VERIFYING.md](docs/VERIFYING.md) — signature checks, source-audit map, network proof, gpg-invocation review.
- [docs/REPRODUCIBLE-BUILD.md](docs/REPRODUCIBLE-BUILD.md) — build from source, compare against the release.
- Every release ships SHA256SUMS for independent checksum verification.

## Contributing

Run `./scripts/setup.sh` to bootstrap the dev environment, then read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).
