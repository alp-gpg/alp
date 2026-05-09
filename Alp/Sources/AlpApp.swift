import SwiftUI

@main
struct AlpApp: App {
    init() {
        // Wire Services menu entries declared in Info.plist to ServicesProvider.
        ServicesProvider.shared.register()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}
