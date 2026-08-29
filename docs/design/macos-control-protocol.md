# macOS control protocol

Status: **internal v1 framing and lifecycle simulation are implemented; no
companion, system extension, or transparent backend uses this protocol yet**.

`heimdall.macos.control/v1` is the narrow control boundary between a future
foreground run session and the signed macOS companion. It registers one run,
waits for provider acknowledgement before command release, unregisters that
run, and removes it when the owner channel closes. It is not a policy language,
network data plane, public daemon API, or transparent-support claim.

## Transport and authorization boundary

The protocol is transport-neutral so the Rust CLI and future Swift companion
can share exact frames. A production transport must provide all of these:

- a private, session-owned channel with a bounded peer and no listening
  machine-wide API;
- operating-system peer identity validation in addition to message HMAC;
- a fresh 32-byte control key delivered through an inherited descriptor or an
  equivalently protected channel, never argv, environment, logs, or disk; and
- confidentiality. HMAC authenticates frames but does not encrypt the relay
  secret inside a registration payload.

The helper owns the channel only for the foreground run. EOF is an owner-death
signal. The last removal requests provider disablement; there is no persistent
user-managed Heimdall daemon.

## Frame

Each message is a four-byte unsigned big-endian length followed by one strict
JSON object. Empty frames and frames above 65,536 bytes are rejected. Unknown
JSON fields are rejected by both the Rust decoder and
[`heimdall.macos.control.v1.schema.json`](../../heimdall/schemas/heimdall.macos.control.v1.schema.json).

```json
{
  "contract": "heimdall.macos.control/v1",
  "direction": "request",
  "session_id": "01890f47-90d4-7cc2-9f5f-6a48f59cf7ab",
  "sequence": 1,
  "operation": "register_run",
  "payload": "<base64url-without-padding>",
  "mac": "<lowercase-hmac-sha256-hex>"
}
```

`session_id` is UUIDv7. Each direction starts at sequence 1 and accepts exactly
the next value; replay, gaps, overflow, a wrong session, a wrong direction, or
an unsupported contract fail closed. Payload is the exact UTF-8 JSON byte
sequence encoded as canonical base64url without padding. Payload JSON field
order is not part of the protocol because HMAC covers the transmitted decoded
bytes.

Operations have fixed directions:

| Code | Operation | Direction | Payload |
| ---: | --- | --- | --- |
| 1 | `register_run` | request | strict run registration |
| 2 | `run_ready` | response | run reference |
| 3 | `unregister_run` | request | run reference |
| 4 | `run_removed` | response | run reference |
| 5 | `error` | response | bounded implementation error |

`run_ready` means the provider acknowledged the exact registration. No current
production component is allowed to emit it.

## HMAC input

HMAC-SHA256 uses the 32-byte session key and this exact byte sequence:

| Field | Encoding |
| --- | --- |
| Contract | UTF-8 `heimdall.macos.control/v1` |
| Separator | one `0x00` byte |
| Direction | request `0x01`, response `0x02` |
| Session | 16 raw UUID bytes |
| Sequence | unsigned 64-bit big-endian |
| Operation | numeric code from the table |
| Payload length | unsigned 32-bit big-endian |
| Payload | decoded payload bytes |

Direction is authenticated and independently constrained by endpoint role, so
a request cannot be reflected as a response. MAC comparison uses the HMAC
implementation's constant-time verifier.

This fixed request is the cross-language conformance vector. The key is bytes
`00` through `1f`, and the decoded payload is
`{"probe":"macos-control-v1"}`.

```json
{"contract":"heimdall.macos.control/v1","direction":"request","session_id":"01890f47-90d4-7cc2-9f5f-6a48f59cf7ab","sequence":1,"operation":"register_run","payload":"eyJwcm9iZSI6Im1hY29zLWNvbnRyb2wtdjEifQ","mac":"eb390e73297ba508ab1ae2ad10cb22bb86d8b92502e277fc2c2e08ee61138569"}
```

## Run registration and lifecycle

A decoded `register_run` payload contains only runtime identity and relay
material:

- UUIDv7 run ID;
- non-zero CLI owner PID, root PID, and process-group ID;
- non-zero process start time plus an absolute executable path for PID-reuse
  checks;
- non-zero loopback relay port and a fresh 32-byte base64url relay secret;
- canonical lowercase SHA-256 policy and config digests; and
- a lease between 1,000 and 30,000 milliseconds.

The companion must independently validate process and peer identity. PIDs,
paths, digests, and secrets in an authenticated frame are registration claims,
not proof that Network Extension attached a flow to that process.

One control session owns one run. Run IDs and process groups are unique while
active. The first registration transitions the provider toward start; a second
run leaves it active; removing a non-final run leaves it active; and only the
last removal transitions it toward stop. A session may remove only its own run.
Clean EOF performs the same exact removal as an explicit unregister.

Portable tests cover the fixed vector, schema, frame bounds, authentication,
tampering, version/direction/session mismatch, replay, invalid registrations,
duplicate process groups, two concurrent runs, explicit removal, and owner EOF.
They do not test Apple entitlements, extension approval, provider messaging, or
flow attribution.

## Attribution gate

Apple defines `NEFlowMetaData.sourceAppAuditToken` as optional. That token is a
candidate signal, not an accepted command-scope contract. Signed native evidence
must prove whether transparent flows provide enough stable metadata
to distinguish the registered process group from unrelated, missing, and
ambiguous sources.

Returning an unknown flow direct can violate fail-closed command policy;
rejecting every unknown flow can disrupt unrelated traffic. Until native
evidence resolves that distinction, the provider remains unwired,
`macos-transparent` remains unselectable, and machine capability output keeps
`strict_command_scope_proven=false`.
