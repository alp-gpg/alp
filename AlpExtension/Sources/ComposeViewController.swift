import MailKit
import SwiftUI

/// MEExtensionViewController that hosts the Liquid Glass compose toolbar panel.
final class ComposeViewController: MEExtensionViewController {
    private var vm: ComposeViewModel?

    func configure(session: MEComposeSession) {
        let viewModel = ComposeViewModel(session: session)
        vm = viewModel
        let hostingView = NSHostingView(rootView: ComposeView(vm: viewModel))
        hostingView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hostingView)
        NSLayoutConstraint.activate([
            hostingView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hostingView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            hostingView.topAnchor.constraint(equalTo: view.topAnchor),
            hostingView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }
}
