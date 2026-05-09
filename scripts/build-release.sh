#!/usr/bin/env bash
# Build, sign, notarize, and package Alp into a DMG.
# Usage: ./scripts/build-release.sh [version]
#   version: e.g. "1.0.0" — defaults to git tag (v prefix stripped)
#
# Required environment:
#   DEVELOPER_ID_APPLICATION  — signing identity, e.g. "Developer ID Application: Name (TEAMID)"
#   APPLE_ID                  — Apple ID for notarization
#   APPLE_ID_PASSWORD         — app-specific password
#   APPLE_TEAM_ID             — Team ID for notarization
set -euo pipefail

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
if [[ -z "$VERSION" ]]; then
    echo "Error: No version provided and no git tag found." >&2
    exit 1
fi

echo "==> Building Alp $VERSION"

ARCHIVE_PATH="build/Alp.xcarchive"
EXPORT_PATH="build/export"
DMG_PATH="build/Alp-${VERSION}.dmg"

rm -rf build
mkdir -p build

# Generate Xcode project
tuist generate --no-open

# Archive
xcodebuild archive \
    -workspace Alp.xcworkspace \
    -scheme Alp \
    -configuration Release \
    -archivePath "$ARCHIVE_PATH" \
    -destination 'generic/platform=macOS' \
    CODE_SIGN_IDENTITY="${DEVELOPER_ID_APPLICATION}" \
    CODE_SIGN_STYLE=Manual \
    DEVELOPMENT_TEAM="${APPLE_TEAM_ID}"

# Export
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist scripts/ExportOptions.plist

APP_PATH="$EXPORT_PATH/Alp.app"

# Notarize
echo "==> Notarizing..."
xcrun notarytool submit "$APP_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_ID_PASSWORD" \
    --wait

# Staple
xcrun stapler staple "$APP_PATH"

# Create DMG
echo "==> Creating DMG..."
create-dmg \
    --volname "Alp" \
    --volicon "$APP_PATH/Contents/Resources/AppIcon.icns" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "Alp.app" 150 200 \
    --app-drop-link 450 200 \
    --no-internet-enable \
    "$DMG_PATH" \
    "$APP_PATH"

# Sign DMG
codesign --force --sign "${DEVELOPER_ID_APPLICATION}" "$DMG_PATH"

# Sparkle signature for the appcast. `sign_update` reads the EdDSA private
# key from the login Keychain (created once via `generate_keys`). Output is
# `sparkle:edSignature="..." length=...` ready to drop into appcast.xml.
SIGN_UPDATE="$(xcrun --find sign_update 2>/dev/null || true)"
if [[ -z "${SIGN_UPDATE}" ]]; then
    SIGN_UPDATE="$(command -v sign_update || true)"
fi
if [[ -n "${SIGN_UPDATE}" ]]; then
    echo "==> Generating Sparkle signature..."
    SPARKLE_LINE="$("$SIGN_UPDATE" "$DMG_PATH")"
    echo "$SPARKLE_LINE" | tee "build/Alp-${VERSION}.sparkle.txt"
    echo "==> Paste the line above into docs/appcast.xml as the <enclosure> attributes."
else
    echo "Warning: sign_update not found on PATH — appcast signature step skipped." >&2
    echo "         Install Sparkle CLI tools or run sign_update manually on $DMG_PATH." >&2
fi

echo "==> Done: $DMG_PATH"
