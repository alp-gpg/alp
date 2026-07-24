#!/usr/bin/env bash
# One-command developer bootstrap for Alp.
#
# Installs every prerequisite (Homebrew packages + GnuPG), generates the
# Xcode project via Tuist, and prints the next steps. Re-runnable: every
# step is idempotent.
#
# Usage:
#   ./scripts/setup.sh

set -euo pipefail

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
note() { printf "  • %s\n" "$*"; }
fail() { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

bold "Checking macOS prerequisites…"

if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "Alp is macOS-only. Detected $(uname -s)."
fi

if ! xcode-select -p >/dev/null 2>&1; then
    fail "Xcode command-line tools not found. Run: xcode-select --install"
fi
note "Xcode CLT present at: $(xcode-select -p)"

if ! command -v brew >/dev/null 2>&1; then
    fail "Homebrew not found. Install from https://brew.sh and re-run."
fi
note "Homebrew at: $(command -v brew)"

bold "Installing Homebrew packages…"
brew_install_if_missing() {
    local pkg="$1"
    if brew list --formula --versions "$pkg" >/dev/null 2>&1 \
        || brew list --cask --versions "$pkg" >/dev/null 2>&1; then
        note "$pkg already installed"
    else
        note "installing $pkg"
        brew install "$pkg"
    fi
}

brew_install_if_missing gnupg
brew_install_if_missing swiftlint
brew_install_if_missing swiftformat
brew_install_if_missing tuist

bold "Verifying GPG keyring…"
if ! gpg --list-secret-keys >/dev/null 2>&1; then
    cat <<EOF
  ! No secret keys found. The test suite needs at least one secret key
    to round-trip encrypt/decrypt. Generate one with:

        gpg --quick-gen-key "Your Name <you@example.com>" default default 0

    or skip this and run Alp's UI tests only.
EOF
else
    note "Found $(gpg --list-secret-keys --with-colons | grep -c '^sec') secret key(s)"
fi

bold "Generating the Xcode project…"
(cd "$(dirname "$0")/.." && tuist generate --no-open)

bold "Done."
cat <<EOF

Next steps:

  1. Open Alp.xcworkspace in Xcode 26:
        open Alp.xcworkspace

  2. Pick the "Alp" scheme and ⌘R to run.

  3. ⌘U to run the test suite (needs gpg and a secret key in your keyring).

  4. Read CONTRIBUTING.md and docs/VERIFYING.md before opening a PR.

EOF
