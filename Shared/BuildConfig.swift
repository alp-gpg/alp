import Foundation

/// App-wide identifiers. Contributors building with their own Team ID
/// can change DEVELOPMENT_TEAM in Project.swift — Xcode's Automatic
/// signing will handle the rest.
enum BuildConfig {
    static let teamID = "3G6WR6H4M5"
    static let helperMachService = "app.alp.Alp.helper"
    static let appGroup = "group.app.alp.Alp"
    static let helperPlistName = "app.alp.Alp.helper.plist"
    static let codeSigningRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
}
