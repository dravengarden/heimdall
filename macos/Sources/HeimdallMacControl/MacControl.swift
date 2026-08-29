import CryptoKit
import Foundation

public let macControlContract = "heimdall.macos.control/v1"

private let maximumFrameBytes = 65_536
private let maximumPayloadBytes = 48_000
private let controlKeyBytes = 32

public enum MacControlDirection: UInt8, Codable, Sendable {
  case request = 1
  case response = 2

  fileprivate var wireName: String {
    switch self {
    case .request: "request"
    case .response: "response"
    }
  }

  fileprivate var opposite: Self {
    switch self {
    case .request: .response
    case .response: .request
    }
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer().decode(String.self)
    switch value {
    case "request": self = .request
    case "response": self = .response
    default:
      throw DecodingError.dataCorruptedError(
        in: try decoder.singleValueContainer(),
        debugDescription: "unknown macOS control direction"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(wireName)
  }
}

public enum MacControlOperation: UInt8, Codable, Sendable {
  case registerRun = 1
  case runReady = 2
  case unregisterRun = 3
  case runRemoved = 4
  case error = 5

  fileprivate var wireName: String {
    switch self {
    case .registerRun: "register_run"
    case .runReady: "run_ready"
    case .unregisterRun: "unregister_run"
    case .runRemoved: "run_removed"
    case .error: "error"
    }
  }

  fileprivate func isAllowed(for direction: MacControlDirection) -> Bool {
    switch (direction, self) {
    case (.request, .registerRun), (.request, .unregisterRun),
      (.response, .runReady), (.response, .runRemoved), (.response, .error):
      true
    default:
      false
    }
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer().decode(String.self)
    switch value {
    case "register_run": self = .registerRun
    case "run_ready": self = .runReady
    case "unregister_run": self = .unregisterRun
    case "run_removed": self = .runRemoved
    case "error": self = .error
    default:
      throw DecodingError.dataCorruptedError(
        in: try decoder.singleValueContainer(),
        debugDescription: "unknown macOS control operation"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(wireName)
  }
}

public struct MacControlEnvelope: Codable, Equatable, Sendable {
  public let contract: String
  public let direction: MacControlDirection
  public let sessionID: UUID
  public let sequence: UInt64
  public let operation: MacControlOperation
  public let payload: String
  public let mac: String

  private enum CodingKeys: String, CodingKey {
    case contract
    case direction
    case sessionID = "session_id"
    case sequence
    case operation
    case payload
    case mac
  }

  public init(
    contract: String,
    direction: MacControlDirection,
    sessionID: UUID,
    sequence: UInt64,
    operation: MacControlOperation,
    payload: String,
    mac: String
  ) {
    self.contract = contract
    self.direction = direction
    self.sessionID = sessionID
    self.sequence = sequence
    self.operation = operation
    self.payload = payload
    self.mac = mac
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    contract = try container.decode(String.self, forKey: .contract)
    direction = try container.decode(MacControlDirection.self, forKey: .direction)
    let session = try container.decode(String.self, forKey: .sessionID)
    guard let parsedSession = UUID(uuidString: session) else {
      throw DecodingError.dataCorruptedError(
        forKey: .sessionID,
        in: container,
        debugDescription: "session_id is not a UUID"
      )
    }
    sessionID = parsedSession
    sequence = try container.decode(UInt64.self, forKey: .sequence)
    operation = try container.decode(MacControlOperation.self, forKey: .operation)
    payload = try container.decode(String.self, forKey: .payload)
    mac = try container.decode(String.self, forKey: .mac)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(contract, forKey: .contract)
    try container.encode(direction, forKey: .direction)
    try container.encode(sessionID.uuidString.lowercased(), forKey: .sessionID)
    try container.encode(sequence, forKey: .sequence)
    try container.encode(operation, forKey: .operation)
    try container.encode(payload, forKey: .payload)
    try container.encode(mac, forKey: .mac)
  }
}

public enum MacControlError: Error, Equatable {
  case authentication
  case contract
  case direction
  case frameJSON
  case frameSize
  case invalidKeyLength
  case invalidSessionID
  case macEncoding
  case operationDirection
  case operationMismatch
  case payloadEncoding
  case payloadTooLarge
  case sequence
  case sequenceExhausted
  case session
}

public struct MacControlSession {
  private let key: SymmetricKey
  private let sessionID: UUID
  private let outbound: MacControlDirection
  private var nextSendSequence: UInt64 = 1
  private var nextReceiveSequence: UInt64 = 1

  public static func requester(secret: Data, sessionID: UUID) throws -> Self {
    try Self(secret: secret, sessionID: sessionID, outbound: .request)
  }

  public static func responder(secret: Data, sessionID: UUID) throws -> Self {
    try Self(secret: secret, sessionID: sessionID, outbound: .response)
  }

  private init(
    secret: Data,
    sessionID: UUID,
    outbound: MacControlDirection
  ) throws {
    guard secret.count == controlKeyBytes else {
      throw MacControlError.invalidKeyLength
    }
    guard isVersionSeven(sessionID) else {
      throw MacControlError.invalidSessionID
    }
    key = SymmetricKey(data: secret)
    self.sessionID = sessionID
    self.outbound = outbound
  }

  public mutating func seal(
    operation: MacControlOperation,
    payload: Data
  ) throws -> MacControlEnvelope {
    guard operation.isAllowed(for: outbound) else {
      throw MacControlError.operationDirection
    }
    guard payload.count <= maximumPayloadBytes else {
      throw MacControlError.payloadTooLarge
    }
    guard nextSendSequence < UInt64.max else {
      throw MacControlError.sequenceExhausted
    }

    let sequence = nextSendSequence
    let input = try authenticationInput(
      direction: outbound,
      sessionID: sessionID,
      sequence: sequence,
      operation: operation,
      payload: payload
    )
    let code = HMAC<SHA256>.authenticationCode(for: input, using: key)
    nextSendSequence += 1

    return MacControlEnvelope(
      contract: macControlContract,
      direction: outbound,
      sessionID: sessionID,
      sequence: sequence,
      operation: operation,
      payload: encodeBase64URL(payload),
      mac: Data(code).lowercaseHex
    )
  }

  public mutating func open(
    expectedOperation: MacControlOperation,
    envelope: MacControlEnvelope
  ) throws -> Data {
    guard envelope.contract == macControlContract else {
      throw MacControlError.contract
    }
    guard envelope.direction == outbound.opposite else {
      throw MacControlError.direction
    }
    guard envelope.operation.isAllowed(for: envelope.direction) else {
      throw MacControlError.operationDirection
    }
    guard envelope.operation == expectedOperation else {
      throw MacControlError.operationMismatch
    }
    guard envelope.sessionID == sessionID else {
      throw MacControlError.session
    }
    guard envelope.sequence == nextReceiveSequence else {
      throw MacControlError.sequence
    }
    guard nextReceiveSequence < UInt64.max else {
      throw MacControlError.sequenceExhausted
    }

    let payload = try decodeBase64URL(envelope.payload)
    guard payload.count <= maximumPayloadBytes else {
      throw MacControlError.payloadTooLarge
    }
    guard encodeBase64URL(payload) == envelope.payload else {
      throw MacControlError.payloadEncoding
    }
    let expectedCode = try decodeLowercaseHex(envelope.mac)
    guard expectedCode.count == controlKeyBytes else {
      throw MacControlError.macEncoding
    }
    let input = try authenticationInput(
      direction: envelope.direction,
      sessionID: envelope.sessionID,
      sequence: envelope.sequence,
      operation: envelope.operation,
      payload: payload
    )
    guard
      HMAC<SHA256>.isValidAuthenticationCode(
        expectedCode,
        authenticating: input,
        using: key
      )
    else {
      throw MacControlError.authentication
    }

    nextReceiveSequence += 1
    return payload
  }
}

public func encodeMacControlFrame(_ envelope: MacControlEnvelope) throws -> Data {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  guard let body = try? encoder.encode(envelope),
    !body.isEmpty,
    body.count <= maximumFrameBytes
  else {
    throw MacControlError.frameSize
  }
  guard let length = UInt32(exactly: body.count) else {
    throw MacControlError.frameSize
  }

  var frame = Data()
  frame.appendBigEndian(length)
  frame.append(body)
  return frame
}

public func decodeMacControlFrame(_ frame: Data) throws -> MacControlEnvelope {
  guard frame.count >= MemoryLayout<UInt32>.size else {
    throw MacControlError.frameSize
  }
  let prefix = [UInt8](frame.prefix(MemoryLayout<UInt32>.size))
  let length = prefix.reduce(UInt32.zero) { partial, byte in
    (partial << 8) | UInt32(byte)
  }
  guard length > 0,
    length <= maximumFrameBytes,
    frame.count == MemoryLayout<UInt32>.size + Int(length)
  else {
    throw MacControlError.frameSize
  }

  let body = Data(frame.dropFirst(MemoryLayout<UInt32>.size))
  guard (try? JSONSerialization.jsonObject(with: body)) is [String: Any] else {
    throw MacControlError.frameJSON
  }
  let keys = try strictTopLevelObjectKeys(body)
  let expectedKeys: Set<String> = [
    "contract", "direction", "session_id", "sequence",
    "operation", "payload", "mac",
  ]
  guard keys.count == expectedKeys.count, Set(keys) == expectedKeys else {
    throw MacControlError.frameJSON
  }
  guard
    let envelope = try? JSONDecoder().decode(
      MacControlEnvelope.self,
      from: body
    )
  else {
    throw MacControlError.frameJSON
  }
  return envelope
}

private func strictTopLevelObjectKeys(_ body: Data) throws -> [String] {
  let bytes = Array(body)
  var index = 0

  func skipWhitespace() {
    while index < bytes.count {
      switch bytes[index] {
      case 9, 10, 13, 32: index += 1
      default: return
      }
    }
  }

  func parseString() throws -> String {
    guard index < bytes.count, bytes[index] == 34 else {
      throw MacControlError.frameJSON
    }
    let start = index
    index += 1
    while index < bytes.count {
      let byte = bytes[index]
      if byte == 92 {
        index += 2
        guard index <= bytes.count else {
          throw MacControlError.frameJSON
        }
        continue
      }
      if byte == 34 {
        index += 1
        let literal = Data(bytes[start..<index])
        guard let value = try? JSONDecoder().decode(String.self, from: literal) else {
          throw MacControlError.frameJSON
        }
        return value
      }
      guard byte >= 32 else {
        throw MacControlError.frameJSON
      }
      index += 1
    }
    throw MacControlError.frameJSON
  }

  func skipScalarValue() throws {
    guard index < bytes.count else {
      throw MacControlError.frameJSON
    }
    if bytes[index] == 34 {
      _ = try parseString()
      return
    }

    let start = index
    while index < bytes.count, bytes[index] != 44, bytes[index] != 125 {
      guard ![91, 93, 123].contains(bytes[index]) else {
        throw MacControlError.frameJSON
      }
      index += 1
    }
    var end = index
    while end > start, [9, 10, 13, 32].contains(bytes[end - 1]) {
      end -= 1
    }
    guard end > start else {
      throw MacControlError.frameJSON
    }
  }

  skipWhitespace()
  guard index < bytes.count, bytes[index] == 123 else {
    throw MacControlError.frameJSON
  }
  index += 1
  skipWhitespace()

  var keys: [String] = []
  while index < bytes.count, bytes[index] != 125 {
    keys.append(try parseString())
    skipWhitespace()
    guard index < bytes.count, bytes[index] == 58 else {
      throw MacControlError.frameJSON
    }
    index += 1
    skipWhitespace()
    try skipScalarValue()
    skipWhitespace()

    if index < bytes.count, bytes[index] == 44 {
      index += 1
      skipWhitespace()
      continue
    }
    guard index < bytes.count, bytes[index] == 125 else {
      throw MacControlError.frameJSON
    }
  }

  guard index < bytes.count, bytes[index] == 125 else {
    throw MacControlError.frameJSON
  }
  index += 1
  skipWhitespace()
  guard index == bytes.count else {
    throw MacControlError.frameJSON
  }
  return keys
}

private func authenticationInput(
  direction: MacControlDirection,
  sessionID: UUID,
  sequence: UInt64,
  operation: MacControlOperation,
  payload: Data
) throws -> Data {
  guard let payloadLength = UInt32(exactly: payload.count) else {
    throw MacControlError.payloadTooLarge
  }

  var input = Data(macControlContract.utf8)
  input.append(0)
  input.append(direction.rawValue)
  input.append(contentsOf: uuidBytes(sessionID))
  input.appendBigEndian(sequence)
  input.append(operation.rawValue)
  input.appendBigEndian(payloadLength)
  input.append(payload)
  return input
}

private func isVersionSeven(_ uuid: UUID) -> Bool {
  let bytes = uuidBytes(uuid)
  return bytes.count == 16
    && (bytes[6] >> 4) == 7
    && (bytes[8] & 0xc0) == 0x80
}

private func uuidBytes(_ uuid: UUID) -> [UInt8] {
  var value = uuid.uuid
  return withUnsafeBytes(of: &value) { Array($0) }
}

private func encodeBase64URL(_ data: Data) -> String {
  data.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

private func decodeBase64URL(_ value: String) throws -> Data {
  guard
    value.utf8.allSatisfy({
      (48...57).contains($0)
        || (65...90).contains($0)
        || (97...122).contains($0)
        || $0 == 45
        || $0 == 95
    })
  else {
    throw MacControlError.payloadEncoding
  }
  var standard =
    value
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  let remainder = standard.utf8.count % 4
  if remainder != 0 {
    standard.append(String(repeating: "=", count: 4 - remainder))
  }
  guard let decoded = Data(base64Encoded: standard) else {
    throw MacControlError.payloadEncoding
  }
  return decoded
}

private func decodeLowercaseHex(_ value: String) throws -> Data {
  let bytes = Array(value.utf8)
  guard bytes.count == controlKeyBytes * 2,
    bytes.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
  else {
    throw MacControlError.macEncoding
  }

  var decoded = Data(capacity: controlKeyBytes)
  for index in stride(from: 0, to: bytes.count, by: 2) {
    decoded.append((hexNibble(bytes[index]) << 4) | hexNibble(bytes[index + 1]))
  }
  return decoded
}

private func hexNibble(_ value: UInt8) -> UInt8 {
  if value <= 57 {
    value - 48
  } else {
    value - 87
  }
}

extension Data {
  fileprivate var lowercaseHex: String {
    map { String(format: "%02x", $0) }.joined()
  }

  fileprivate mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
    var encoded = value.bigEndian
    Swift.withUnsafeBytes(of: &encoded) { append(contentsOf: $0) }
  }
}
