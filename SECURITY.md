# Security Policy

Alp handles GPG key material and passphrases. We take security reports
seriously and ask you to follow coordinated disclosure.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Please use GitHub's private vulnerability reporting:

1. Go to <https://github.com/alp-gpg/alp/security/advisories/new>
2. Click "Report a vulnerability"

Alternatively, email **security@alp-gpg.github.io** with:

- A description of the issue and its impact
- Steps to reproduce (proof of concept, if applicable)
- Affected version(s)

If you want encrypted communication, send your report PGP-encrypted to
the release-signing key. You can fetch it from:

```
gpg --locate-keys security@alp-gpg.github.io
```

(Or download it from the GitHub release pages — every `SHA256SUMS.asc`
is signed by the same key.)

## Response Timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix or mitigation:** target 30 days for high-severity, 90 days for
  low-severity. Complex issues may take longer; we'll keep you informed.

## Scope

- Alp (the macOS app, Mail extension, XPC helper, and pinentry)
- The release pipeline (`scripts/build-release.sh`, GitHub Actions
  workflows)
- The update distribution channel (`release.json` signing, GitHub Pages)

Out of scope: vulnerabilities in GnuPG itself (report to the GnuPG
project), vulnerabilities in macOS or Apple frameworks (report to
Apple).

## Safe Harbor

We will not take legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data
  destruction, and service interruption
- Give us reasonable time to remediate before public disclosure
- Do not demand payment in exchange for withholding disclosure

## Disclosure

Once a fix is released, we publish a GitHub Security Advisory with
credit to the reporter (unless they prefer to remain anonymous).
