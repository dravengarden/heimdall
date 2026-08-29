import Foundation
import NetworkExtension
import os

private let prototypeErrorDomain =
  "io.github.dravengarden.heimdall.transparent-proxy.prototype"

final class TransparentProxyProvider: NETransparentProxyProvider {
  private let logger = Logger(
    subsystem: "io.github.dravengarden.heimdall",
    category: "transparent-probe"
  )

  override func startProxy(
    options: [String: Any]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    // Why: an installed compile probe must never become a routing claim.
    // Startup remains fail-closed until signed native attribution evidence
    // and the authenticated run-registration transport both exist.
    completionHandler(prototypeError(code: 1, message: "prototype activation is disabled"))
  }

  override func stopProxy(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    completionHandler()
  }

  override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
    let snapshot = FlowMetadataSnapshot(flow: flow)
    logger.notice("blocked unexpected prototype flow")
    logger.notice("transport=\(snapshot.transport, privacy: .public)")
    logger.notice("audit_token=\(snapshot.hasAuditToken, privacy: .public)")
    logger.notice(
      "signing_id=\(snapshot.hasSigningIdentifier, privacy: .public)"
    )
    logger.notice(
      "unique_id=\(snapshot.hasUniqueIdentifier, privacy: .public)"
    )

    // Why: returning false asks the operating system to send the flow by
    // its normal route. That would turn missing attribution into a policy
    // bypass if this prototype were ever configured accidentally.
    let error = prototypeError(code: 2, message: "prototype flow blocked")
    flow.closeReadWithError(error)
    flow.closeWriteWithError(error)
    return true
  }
}

private struct FlowMetadataSnapshot {
  let transport: String
  let hasAuditToken: Bool
  let hasSigningIdentifier: Bool
  let hasUniqueIdentifier: Bool

  init(flow: NEAppProxyFlow) {
    if flow is NEAppProxyTCPFlow {
      transport = "tcp"
    } else if flow is NEAppProxyUDPFlow {
      transport = "udp"
    } else {
      transport = "unknown"
    }
    hasAuditToken = flow.metaData.sourceAppAuditToken != nil
    hasSigningIdentifier = !flow.metaData.sourceAppSigningIdentifier.isEmpty
    hasUniqueIdentifier = !flow.metaData.sourceAppUniqueIdentifier.isEmpty
  }
}

private func prototypeError(code: Int, message: String) -> NSError {
  NSError(
    domain: prototypeErrorDomain,
    code: code,
    userInfo: [NSLocalizedDescriptionKey: message]
  )
}
