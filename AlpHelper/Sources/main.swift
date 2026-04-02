import Foundation

final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Only accept connections from processes signed by the same Team ID.
        connection.setCodeSigningRequirement(BuildConfig.codeSigningRequirement)

        connection.exportedInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.exportedObject = GPGHelper()
        connection.resume()
        return true
    }
}

let listener = NSXPCListener(machServiceName: BuildConfig.helperMachService)
let delegate = HelperDelegate()
listener.delegate = delegate
listener.resume()
dispatchMain()
