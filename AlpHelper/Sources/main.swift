import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp.helper", category: "XPC")

final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    func listener(
        _: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection,
    ) -> Bool {
        // Only accept connections from processes signed by the same Team ID.
        // If this requirement fails the system terminates the connection before
        // any reply is sent — we do not get a callback for those rejections,
        // but we do log the accepted ones so a security audit has a trail of
        // every client that successfully attached to the helper.
        connection.setCodeSigningRequirement(BuildConfig.codeSigningRequirement)

        connection.exportedInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.exportedObject = GPGHelper()

        let pid = connection.processIdentifier
        log.info("XPC connection accepted from pid \(pid, privacy: .public)")
        connection.invalidationHandler = {
            log.info("XPC connection from pid \(pid, privacy: .public) invalidated")
        }
        connection.interruptionHandler = {
            log.info("XPC connection from pid \(pid, privacy: .public) interrupted")
        }

        connection.resume()
        return true
    }
}

let listener = NSXPCListener(machServiceName: BuildConfig.helperMachService)
let delegate = HelperDelegate()
listener.delegate = delegate
listener.resume()
dispatchMain()
