import Foundation
import ServiceManagement

enum HelperInstaller {
    /// One code path for every configuration. Debug used to bootstrap the helper
    /// with launchctl instead, which meant nobody ever exercised SMAppService
    /// outside a release build — and release builds could not register at all.
    static func install() throws {
        try SMAppService.agent(plistName: BuildConfig.helperPlistName).register()
    }

    static func uninstall() throws {
        try SMAppService.agent(plistName: BuildConfig.helperPlistName).unregister()
    }
}
