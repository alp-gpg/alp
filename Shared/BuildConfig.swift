import Foundation

/// Compile-time identifiers injected via Xcode build settings.
/// Values are set in Project.swift and propagated through Info.plist variables.
///
/// To customize for your own build, change `teamID` and `bundlePrefix`
/// at the top of Project.swift — all other references derive from them.
enum BuildConfig {
    /// Apple Developer Team ID (e.g. "ABCDE12345").
    /// Set via ALP_TEAM_ID build setting.
    static let teamID: String = Bundle.main.object(forInfoDictionaryKey: "ALPTeamID") as? String ?? ""

    /// Bundle ID prefix (e.g. "com.example").
    /// Set via ALP_BUNDLE_PREFIX build setting.
    static let bundlePrefix: String = Bundle.main.object(forInfoDictionaryKey: "ALPBundlePrefix") as? String ?? ""

    /// Mach service name for the XPC helper.
    static let helperMachService: String = "\(bundlePrefix).alp.helper"

    /// App group identifier shared between the app and extension.
    static let appGroup: String = "group.\(bundlePrefix).alp"

    /// LaunchAgent plist filename (must match the file in AlpHelper/SupportingFiles/).
    static let helperPlistName: String = "\(bundlePrefix).alp.helper.plist"

    /// Code signing requirement for XPC connections.
    static let codeSigningRequirement: String =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
}
