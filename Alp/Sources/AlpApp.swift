import AppKit
import Sparkle
import SwiftUI

@main
struct AlpApp: App {
    /// Wires Services menu registration after NSApplication has been
    /// created. Touching `NSApp` from `App.init()` crashes because the
    /// implicitly-unwrapped global is still nil that early in launch.
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    /// Sparkle drives auto-update for direct-DMG installs (brew users get
    /// updates from `brew upgrade`). The controller has to be a stored
    /// property so its lifetime spans the whole app session.
    private let updaterController: SPUStandardUpdaterController

    init() {
        // `startingUpdater: true` schedules background checks per the cadence
        // the user picked in the Sparkle preferences pane (or our default).
        // Sparkle reads SUFeedURL and SUPublicEDKey from Info.plist directly.
        updaterController = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil,
        )
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(after: .appInfo) {
                // Sparkle no-ops when a check is already in progress, so we
                // skip the "disable while running" binding the docs suggest —
                // the KVO key path it relies on isn't compatible with Swift 6
                // strict-concurrency main-actor isolation, and the polish is
                // not worth a custom NSObject observer.
                Button("Check for Updates…") {
                    updaterController.checkForUpdates(nil)
                }
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
