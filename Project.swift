import ProjectDescription

let baseSettings: SettingsDictionary = [
    "SWIFT_VERSION": "6.3",
    "SWIFT_STRICT_CONCURRENCY": "complete",
    "MACOSX_DEPLOYMENT_TARGET": "26.0",
    "ALWAYS_SEARCH_USER_PATHS": "NO",
    "ENABLE_TESTABILITY": "YES",
    "ENABLE_HARDENED_RUNTIME": "YES",
    "ENABLE_USER_SCRIPT_SANDBOXING": "YES",
    "SWIFT_EMIT_LOC_STRINGS": "YES",
    // Generate type-safe accessors for every entry in
    // Localizable.xcstrings so SwiftUI code can reference strings as
    // properties instead of as stringly-typed keys.
    "LOCALIZED_STRING_SWIFTUI_SUPPORT": "YES",
    "STRING_CATALOG_GENERATE_SYMBOLS": "YES",
    "CURRENT_PROJECT_VERSION": "1",
    "VERSIONING_SYSTEM": "apple-generic",
]

let project = Project(
    name: "Alp",
    options: .options(
        defaultKnownRegions: ["en"],
        developmentRegion: "en",
    ),
    packages: [
        // Sparkle 2 powers auto-update for direct-DMG installs. brew users
        // upgrade via `brew upgrade --cask`; Sparkle covers everyone else.
        .remote(
            url: "https://github.com/sparkle-project/Sparkle",
            requirement: .upToNextMajor(from: "2.9.2"),
        ),
    ],
    settings: .settings(base: baseSettings),
    targets: [
        // ── Main App ───────────────────────────────────────────────────
        .target(
            name: "Alp",
            destinations: .macOS,
            product: .app,
            bundleId: "app.alp.Alp",
            deploymentTargets: .macOS("26.0"),
            infoPlist: .file(path: "Alp/SupportingFiles/Info.plist"),
            sources: ["Alp/Sources/**", "Shared/**"],
            resources: ["Alp/Resources/**"],
            entitlements: .file(path: "Alp/SupportingFiles/Alp.entitlements"),
            scripts: [
                // SMAppService.agent(plistName:) requires the launchd plist at
                // Contents/Library/LaunchAgents/ inside the app bundle.
                .post(
                    script: """
                    DEST="${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Library/LaunchAgents"
                    mkdir -p "$DEST"
                    cp "${SRCROOT}/AlpHelper/SupportingFiles/app.alp.Alp.helper.plist" \
                       "$DEST/app.alp.Alp.helper.plist"
                    """,
                    name: "Copy LaunchAgent plist",
                    inputPaths: ["$(SRCROOT)/AlpHelper/SupportingFiles/app.alp.Alp.helper.plist"],
                    outputPaths: [
                        "$(BUILT_PRODUCTS_DIR)/$(CONTENTS_FOLDER_PATH)/Library/LaunchAgents/app.alp.Alp.helper.plist",
                    ],
                    basedOnDependencyAnalysis: false,
                ),
                // Embed the AlpHelper command-line tool inside the app bundle so
                // SMAppService can locate it via BundleProgram = Contents/MacOS/AlpHelper.
                // Xcode's final bundle-signing step will re-sign the copied binary.
                .post(
                    script: """
                    cp "${BUILT_PRODUCTS_DIR}/AlpHelper" \
                       "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/MacOS/AlpHelper"
                    """,
                    name: "Embed AlpHelper",
                    inputPaths: ["$(BUILT_PRODUCTS_DIR)/AlpHelper"],
                    outputPaths: ["$(BUILT_PRODUCTS_DIR)/$(CONTENTS_FOLDER_PATH)/MacOS/AlpHelper"],
                    basedOnDependencyAnalysis: false,
                ),
                // Embed the AlpPinentry command-line tool. gpg-agent will
                // execute this binary via a stable shim path the
                // `configurePinentry` helper RPC writes into the user's
                // gpg-agent.conf, so it must live somewhere predictable
                // inside the bundle.
                .post(
                    script: """
                    DEST="${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Helpers"
                    mkdir -p "$DEST"
                    cp "${BUILT_PRODUCTS_DIR}/AlpPinentry" "$DEST/AlpPinentry"
                    """,
                    name: "Embed AlpPinentry",
                    inputPaths: ["$(BUILT_PRODUCTS_DIR)/AlpPinentry"],
                    outputPaths: ["$(BUILT_PRODUCTS_DIR)/$(CONTENTS_FOLDER_PATH)/Helpers/AlpPinentry"],
                    basedOnDependencyAnalysis: false,
                ),
            ],
            dependencies: [
                .target(name: "AlpExtension"),
                .target(name: "AlpHelper"),
                .target(name: "AlpPinentry"),
                .package(product: "Sparkle"),
            ],
            settings: .settings(
                base: [
                    "CODE_SIGN_IDENTITY": "Apple Development",
                    "CODE_SIGN_STYLE": "Automatic",
                    "DEVELOPMENT_TEAM": "3G6WR6H4M5",
                    "ENABLE_HARDENED_RUNTIME": "YES",
                    // Xcode 26 surfaces app-group membership in the
                    // provisioning profile via this flag. Without it the
                    // settings-side capabilities pane keeps nagging.
                    "ENABLE_APP_GROUPS": "YES",
                ],
                configurations: [
                    .debug(
                        name: "Debug",
                        settings: [
                            // Disable sandbox so launchctl bootstrap works from DerivedData.
                            "CODE_SIGN_ENTITLEMENTS": "Alp/SupportingFiles/AlpDebug.entitlements",
                        ],
                    ),
                    .release(
                        name: "Release",
                        settings: [
                            "CODE_SIGN_ENTITLEMENTS": "Alp/SupportingFiles/Alp.entitlements",
                        ],
                    ),
                ],
            ),
        ),

        // ── Mail Extension ─────────────────────────────────────────────
        .target(
            name: "AlpExtension",
            destinations: .macOS,
            product: .appExtension,
            bundleId: "app.alp.Alp.extension",
            deploymentTargets: .macOS("26.0"),
            infoPlist: .file(path: "AlpExtension/SupportingFiles/Info.plist"),
            sources: [
                "AlpExtension/Sources/**",
                "Shared/**",
            ],
            resources: ["AlpExtension/Resources/**"],
            entitlements: .file(path: "AlpExtension/SupportingFiles/AlpExtension.entitlements"),
            settings: .settings(base: [
                "CODE_SIGN_IDENTITY": "Apple Development",
                "CODE_SIGN_STYLE": "Automatic",
                "DEVELOPMENT_TEAM": "3G6WR6H4M5",
                "ENABLE_HARDENED_RUNTIME": "YES",
                "ENABLE_APP_GROUPS": "YES",
            ]),
        ),

        // ── XPC Helper Daemon ──────────────────────────────────────────
        .target(
            name: "AlpHelper",
            destinations: .macOS,
            product: .commandLineTool,
            bundleId: "app.alp.Alp.helper",
            deploymentTargets: .macOS("26.0"),
            infoPlist: .file(path: "AlpHelper/SupportingFiles/Info.plist"),
            sources: [
                "AlpHelper/Sources/**",
                "Shared/**",
            ],
            // No resources, no entitlements = no sandbox (needs exec + filesystem for gpg)
            settings: .settings(base: [
                "CODE_SIGN_IDENTITY": "Apple Development",
                "CODE_SIGN_STYLE": "Automatic",
                "DEVELOPMENT_TEAM": "3G6WR6H4M5",
                "ENABLE_HARDENED_RUNTIME": "YES",
                "CREATE_INFOPLIST_SECTION_IN_BINARY": "YES",
                "OTHER_CODE_SIGN_FLAGS": "--identifier app.alp.Alp.helper",
            ]),
        ),

        // ── Pinentry (Assuan-speaking GUI passphrase prompt) ──────────
        .target(
            name: "AlpPinentry",
            destinations: .macOS,
            product: .commandLineTool,
            bundleId: "app.alp.Alp.pinentry",
            deploymentTargets: .macOS("26.0"),
            infoPlist: .file(path: "AlpPinentry/SupportingFiles/Info.plist"),
            sources: [
                "AlpPinentry/Sources/**",
            ],
            // No entitlements: pinentry runs as a child of gpg-agent in
            // the user's session and only needs Cocoa for the secure
            // text field. No sandbox, no XPC, no network.
            settings: .settings(base: [
                "CODE_SIGN_IDENTITY": "Apple Development",
                "CODE_SIGN_STYLE": "Automatic",
                "DEVELOPMENT_TEAM": "3G6WR6H4M5",
                "ENABLE_HARDENED_RUNTIME": "YES",
                "CREATE_INFOPLIST_SECTION_IN_BINARY": "YES",
                "OTHER_CODE_SIGN_FLAGS": "--identifier app.alp.Alp.pinentry",
            ]),
        ),

        // ── Tests ──────────────────────────────────────────────────────
        // AlpHelper is a command-line tool and cannot be linked as a framework.
        // Compile its sources (excluding main.swift) directly into the test target.
        .target(
            name: "AlpTests",
            destinations: .macOS,
            product: .unitTests,
            bundleId: "app.alp.Alp.tests",
            deploymentTargets: .macOS("26.0"),
            sources: [
                .glob("Tests/**"),
                .glob("AlpHelper/Sources/**", excluding: ["AlpHelper/Sources/main.swift"]),
                .glob("Alp/Sources/**", excluding: ["Alp/Sources/AlpApp.swift"]),
                .glob("Shared/**"),
            ],
            dependencies: [],
        ),
    ],
)
