import Foundation
import ServiceManagement

enum HelperInstaller {
    enum InstallError: LocalizedError {
        case helperBinaryNotFound(String)
        case launchctlFailed(String)
        case plistWriteFailed(String)

        var errorDescription: String? {
            switch self {
            case let .helperBinaryNotFound(path):
                "Helper binary not found at \(path)"
            case let .launchctlFailed(stderr):
                "launchctl failed: \(stderr)"
            case let .plistWriteFailed(reason):
                "Could not write debug plist: \(reason)"
            }
        }
    }

    // MARK: – Public

    static func install() throws {
        #if DEBUG
            try installDebug()
        #else
            try SMAppService.agent(plistName: BuildConfig.helperPlistName).register()
        #endif
    }

    static func uninstall() throws {
        #if DEBUG
            uninstallDebug()
        #else
            try SMAppService.agent(plistName: BuildConfig.helperPlistName).unregister()
        #endif
    }

    // MARK: – Debug

    #if DEBUG
        private static let debugPlistURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents")
            .appendingPathComponent(BuildConfig.helperPlistName)

        private static func installDebug() throws {
            // Use the standalone-built AlpHelper binary in the build products dir
            // (next to Alp.app), NOT the copy embedded inside the app bundle.
            // The embedded copy gets re-signed during app bundle signing which
            // breaks its code signature for standalone launchd execution
            // (OS_REASON_CODESIGNING).
            let helperBinary = Bundle.main.bundleURL
                .deletingLastPathComponent()
                .appendingPathComponent("AlpHelper").path

            guard FileManager.default.isExecutableFile(atPath: helperBinary) else {
                throw InstallError.helperBinaryNotFound(helperBinary)
            }

            // Build plist with absolute Program path (not relative BundleProgram).
            let plist: [String: Any] = [
                "Label": BuildConfig.helperMachService,
                "Program": helperBinary,
                "MachServices": [BuildConfig.helperMachService: true],
            ]

            let dir = debugPlistURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

            let data = try PropertyListSerialization.data(
                fromPropertyList: plist, format: .xml, options: 0,
            )
            do {
                try data.write(to: debugPlistURL, options: .atomic)
            } catch {
                throw InstallError.plistWriteFailed(error.localizedDescription)
            }

            // Bootout any stale registration (ignore errors — may not exist).
            let uid = getuid()
            launchctl(["bootout", "gui/\(uid)/\(BuildConfig.helperMachService)"])

            // Bootstrap the generated plist.
            let (status, stderr) = launchctl(
                ["bootstrap", "gui/\(uid)", debugPlistURL.path],
            )
            guard status == 0 else {
                throw InstallError.launchctlFailed(stderr)
            }
            print("[Alp] DEBUG: bootstrapped helper at \(helperBinary)")
        }

        private static func uninstallDebug() {
            let uid = getuid()
            launchctl(["bootout", "gui/\(uid)/\(BuildConfig.helperMachService)"])
            try? FileManager.default.removeItem(at: debugPlistURL)
            print("[Alp] DEBUG: removed helper registration")
        }

        @discardableResult
        private static func launchctl(_ arguments: [String]) -> (status: Int32, stderr: String) {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            proc.arguments = arguments
            // Minimal environment — absolute binary, no user input in args,
            // but keep consistent with the helper's sanitizedEnvironment()
            // hygiene even in DEBUG.
            proc.environment = ["HOME": NSHomeDirectory(), "PATH": "/bin:/usr/bin"]
            let errPipe = Pipe()
            proc.standardError = errPipe
            proc.standardOutput = nil
            try? proc.run()
            proc.waitUntilExit()
            let stderr = String(
                data: errPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8,
            ) ?? ""
            return (proc.terminationStatus, stderr)
        }
    #endif
}
