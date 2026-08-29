import Foundation
import Testing

@testable import HeimdallMacControl

private let fixedSessionID = UUID(
  uuidString: "01890f47-90d4-7cc2-9f5f-6a48f59cf7ab"
)!
private let fixedKey = Data(0..<32)
private let fixedPayload = Data(#"{"probe":"macos-control-v1"}"#.utf8)

private func frame(body: Data) -> Data {
  var length = UInt32(body.count).bigEndian
  var frame = withUnsafeBytes(of: &length) { Data($0) }
  frame.append(body)
  return frame
}

@Test func rustFixedVectorMatches() throws {
  var requester = try MacControlSession.requester(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  let envelope = try requester.seal(
    operation: .registerRun,
    payload: fixedPayload
  )

  #expect(envelope.contract == "heimdall.macos.control/v1")
  #expect(envelope.direction == .request)
  #expect(envelope.sessionID == fixedSessionID)
  #expect(envelope.sequence == 1)
  #expect(envelope.operation == .registerRun)
  #expect(envelope.payload == "eyJwcm9iZSI6Im1hY29zLWNvbnRyb2wtdjEifQ")
  #expect(
    envelope.mac
      == "eb390e73297ba508ab1ae2ad10cb22bb86d8b92502e277fc2c2e08ee61138569"
  )
}

@Test func framedEnvelopeRoundTripsStrictly() throws {
  var requester = try MacControlSession.requester(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  let envelope = try requester.seal(
    operation: .registerRun,
    payload: fixedPayload
  )

  let frame = try encodeMacControlFrame(envelope)
  let decoded = try decodeMacControlFrame(frame)

  #expect(decoded == envelope)
}

@Test func responderAuthenticatesOneRequestExactlyOnce() throws {
  var requester = try MacControlSession.requester(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  var responder = try MacControlSession.responder(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  let envelope = try requester.seal(
    operation: .registerRun,
    payload: fixedPayload
  )

  #expect(
    try responder.open(
      expectedOperation: .registerRun,
      envelope: envelope
    ) == fixedPayload
  )
  #expect(throws: MacControlError.sequence) {
    try responder.open(
      expectedOperation: .registerRun,
      envelope: envelope
    )
  }
}

@Test func authenticationRejectsTampering() throws {
  var responder = try MacControlSession.responder(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  let tampered = MacControlEnvelope(
    contract: macControlContract,
    direction: .request,
    sessionID: fixedSessionID,
    sequence: 1,
    operation: .registerRun,
    payload: "e30",
    mac: "eb390e73297ba508ab1ae2ad10cb22bb86d8b92502e277fc2c2e08ee61138569"
  )

  #expect(throws: MacControlError.authentication) {
    try responder.open(
      expectedOperation: .registerRun,
      envelope: tampered
    )
  }
}

@Test func frameRejectsUnknownFields() throws {
  let body = Data(
    #"{"contract":"heimdall.macos.control/v1","direction":"request","session_id":"01890f47-90d4-7cc2-9f5f-6a48f59cf7ab","sequence":1,"operation":"register_run","payload":"e30","mac":"0000000000000000000000000000000000000000000000000000000000000000","unexpected":true}"#
      .utf8
  )
  #expect(throws: MacControlError.frameJSON) {
    try decodeMacControlFrame(frame(body: body))
  }
}

@Test func frameRejectsDuplicateFields() throws {
  var requester = try MacControlSession.requester(
    secret: fixedKey,
    sessionID: fixedSessionID
  )
  let encoded = try encodeMacControlFrame(
    requester.seal(operation: .registerRun, payload: fixedPayload)
  )
  let original = String(
    decoding: encoded.dropFirst(MemoryLayout<UInt32>.size),
    as: UTF8.self
  )
  let duplicate = Data(
    (#"{"contract":"heimdall.macos.control/v1","# + original.dropFirst()).utf8
  )

  #expect(throws: MacControlError.frameJSON) {
    try decodeMacControlFrame(frame(body: duplicate))
  }
}

@Test func sessionRequiresVersionSevenAndExactKeyLength() {
  #expect(throws: MacControlError.invalidKeyLength) {
    try MacControlSession.requester(
      secret: Data(repeating: 0, count: 31),
      sessionID: fixedSessionID
    )
  }
  #expect(throws: MacControlError.invalidSessionID) {
    try MacControlSession.requester(
      secret: fixedKey,
      sessionID: UUID()
    )
  }
}
