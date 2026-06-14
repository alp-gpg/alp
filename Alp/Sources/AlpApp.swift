import AppKit
import SwiftUI

@main
struct AlpApp: App {
    /// Wires Services menu registration after NSApplication has been
    /// created. Touching `NSApp` from `App.init()` crashes because the
    /// implicitly-unwrapped global is still nil that early in launch.
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    /// Notification-only updater (replaced Sparkle). Shared so the General
    /// settings pane can show the current update state and the menu can
    /// trigger a manual check.
    @State private var updateChecker = UpdateChecker()
    @AppStorage("AlpAutomaticUpdateChecks") private var automaticUpdateChecks = false

    var body: some Scene {
        // A single `Window`, not `WindowGroup`: Alp is a settings-style app, so
        // File ▸ New Window must not spawn independent windows each with their
        // own SettingsViewModel and periodic health-check loop (which could
        // then disagree about helper status). One window, one model (§4.1).
        Window("Alp", id: "main") {
            ContentView()
                .environment(updateChecker)
                .task {
                    if automaticUpdateChecks { updateChecker.startAutomaticChecks() }
                }
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    Task { await updateChecker.check(manual: true) }
                }
                .disabled(updateChecker.isChecking)
            }
        }
    }
}

/// AppKit lifecycle hooks that need a real NSApplication. Anything wired
/// here runs after the run loop is up and `NSApp` is non-nil.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        ServicesProvider.shared.register()
    }
}
