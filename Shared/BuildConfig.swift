import Foundation

/// App-wide identifiers. Contributors building with their own Team ID
/// can change DEVELOPMENT_TEAM in Project.swift — Xcode's Automatic
/// signing will handle the rest.
enum BuildConfig {
    static let teamID = "3G6WR6H4M5"
    static let helperMachService = "app.alp.Alp.helper"
    static let appGroup = "group.app.alp.Alp"
    static let helperPlistName = "app.alp.Alp.helper.plist"

    static let appBundleID = "app.alp.Alp"
    static let extensionBundleID = "app.alp.Alp.extension"
    static let helperBundleID = "app.alp.Alp.helper"

    private static let teamAnchor =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""

    /// Requirement used by the app and the Mail extension to validate that
    /// the peer they're connecting to is the Alp helper signed by us. Pinning
    /// the bundle identifier prevents a same-Team-ID binary other than the
    /// helper from impersonating the XPC server.
    static let helperRequirement =
        "\(teamAnchor) and identifier \"\(helperBundleID)\""

    /// Requirement used by the helper to validate incoming connections. The
    /// helper accepts either the main app (settings UI) or the Mail extension
    /// — no other same-Team-ID binary should be able to attach.
    static let clientRequirement =
        "\(teamAnchor) and (identifier \"\(appBundleID)\" or identifier \"\(extensionBundleID)\")"
}
