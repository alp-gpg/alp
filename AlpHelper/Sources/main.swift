import Foundation

final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Only accept connections from processes signed by the same Team ID.
        connection.setCodeSigningRequirement(
            "anchor apple generic and certificate leaf[subject.OU] = \"3G6WR6H4M5\""
        )

        connection.exportedInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.exportedObject = GPGHelper()
        connection.resume()
        return true
    }
}

let listener = NSXPCListener(machServiceName: "com.CXM87Z432P.alp.helper")
let delegate = HelperDelegate()
listener.delegate = delegate
listener.resume()
dispatchMain()
