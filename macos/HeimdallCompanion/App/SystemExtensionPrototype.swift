import SystemExtensions

enum SystemExtensionPrototype {
  static let extensionIdentifier =
    "io.github.dravengarden.heimdall.transparent-proxy"

  static func makeActivationRequest(
    delegate: any OSSystemExtensionRequestDelegate
  ) -> OSSystemExtensionRequest {
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: extensionIdentifier,
      queue: .main
    )
    request.delegate = delegate
    return request
  }
}
