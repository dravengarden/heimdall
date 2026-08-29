import SwiftUI

@main
struct HeimdallCompanionApp: App {
  var body: some Scene {
    WindowGroup {
      VStack(alignment: .leading, spacing: 16) {
        Text("Heimdall transparent proxy")
          .font(.title2.weight(.semibold))
        Text("Prototype only")
          .font(.headline)
          .foregroundColor(.secondary)
        Text(
          "The provider bundle is present for unsigned build validation. "
            + "Activation, routing, and command-scope claims remain disabled."
        )
        .fixedSize(horizontal: false, vertical: true)
        Label("No network settings are installed", systemImage: "lock.shield")
        Label("No background Heimdall daemon is started", systemImage: "terminal")
      }
      .padding(24)
      .frame(minWidth: 460, maxWidth: 560, alignment: .leading)
    }
  }
}
