# Event and run schemas

The daemonless event store records lifecycle, TCP/UDP flow metadata, bounded
content-addressed payload blobs, correlated fake-DNS and policy evidence,
OpenSSL runtime observations, relay ClientHello, and relay TLS handshake/error
evidence in `heimdall.event/v1`, including bounded HTTP/1 headers derived from
explicit TLS plaintext. Inspect
`agent.capabilities.logs` and use [commands.md](commands.md) whenever required
evidence is not yet emitted.

The complete lifecycle, rotation, retention, and security design is in
[`../../../docs/design/agent-event-log.md`](../../../docs/design/agent-event-log.md).
This reference is the agent-facing schema map.

## Discovery contract

Never hard-code an XDG path. Discover the active contracts and paths from
`heimdall agent`, then execute its actions as argv arrays.

```text
heimdall logs schema --event v1
heimdall logs schema --run v1
heimdall logs summary --run RUN_ID --json
heimdall logs path --run RUN_ID --json
```

The two schema commands each print one JSON Schema Draft 2020-12 document.
`logs summary` prints one `heimdall.logs.summary/v1` operational aggregation;
it does not replace integrity verification. `logs path` prints one result
document containing an absolute `run_dir`.

## `heimdall.event/v1`

Every physical line in every `events-NNNNNN.jsonl` file is one UTF-8 JSON
object followed by `\n`.

Required common fields:

| Field | Type | Constraint |
| --- | --- | --- |
| `schema` | string | `heimdall.event/v1` |
| `run_id` | UUIDv7 string | Constant within a run |
| `seq` | unsigned integer | Starts at 1, strictly increments by 1 |
| `ts` | string | RFC 3339 UTC, microseconds, trailing `Z` |
| `monotonic_ns` | unsigned integer | Nanoseconds from this run's origin |
| `kind` | string enum | One of the v1 kinds below |
| `data` | object | Kind-specific strict object |

Conditional common fields:

| Field | Type | Constraint |
| --- | --- | --- |
| `flow_id` | UUIDv7 string | Required for flow, TLS, payload, and HTTP kinds |
| `pid` | unsigned integer | Optional observation; not durable identity |

V1 kinds:

```text
run.open
run.ready
run.exec
run.warning
run.error
run.close
dns.query
dns.answer
policy.decision
flow.open
flow.data
flow.close
tls.runtime
tls.client_hello
tls.handshake
tls.error
http.request
http.response
```

Do not treat an unknown kind as a known v1 kind. Stop and obtain the schema
that matches the record's `schema` value.

### Kind data contracts

The checked-in schema must define these required v1 fields. Fields marked
nullable are still present so an agent can distinguish unavailable data from a
producer version mismatch.

| Kind | Required `data` fields |
| --- | --- |
| `run.open` | `policy` string, `backend` string, `capture` object, `schemas` object |
| `run.ready` | `listeners` object with `owner` and nullable `control`, `boundaries` string array |
| `run.exec` | `child_pid` unsigned integer, `executable` string, `argv_count` unsigned integer |
| `run.warning` | `code` string, `message` string, `phase` string, `context` object |
| `run.error` | `code` string, `message` string, `phase` string, `retryable` boolean, `context` object |
| `run.close` | `exit_code` integer or null, `signal` integer or null, `descendants_cleaned` boolean, `complete` boolean |
| `dns.query` | `exchange_id` UUIDv7, `transport` enum, `questions` array, `policy` string |
| `dns.answer` | `exchange_id` UUIDv7, `rcode` string, `answers` array, `boundary` enum, `latency_us` unsigned integer |
| `policy.decision` | `source` object, `policy` string, `network` enum, `destination` object, `rule` object, `action` object |
| `flow.open` | `network` enum, `source` object, `destination` object, `action` object, `policy` string, `boundary` enum |
| `flow.data` | `direction` enum, `boundary` enum, `original_bytes` unsigned integer, `stored_bytes` unsigned integer, `truncated` boolean, `blob` object or null |
| `flow.close` | `network` enum, `status` string, `error_code` string or null, `client_to_remote_bytes` unsigned integer, `remote_to_client_bytes` unsigned integer, `duration_us` unsigned integer |
| `tls.runtime` | `library` string, `api_family` enum, `direction` enum, `boundary` constant, observed/reported byte counts, `truncated` boolean |
| `tls.client_hello` | `sni` string or null, `alpn_offered` string array, null version bounds, `parser_status=parsed_versions_unavailable` |
| `tls.handshake` | `mode` enum, `version` string, `cipher` string, `alpn` string or null, `peer_identity` object, `trust` object, `latency_us` unsigned integer |
| `tls.error` | `mode` enum, `code` string, `message` string, `phase` string, `retryable` boolean, `peer_identity` object or null |
| `http.request` | `parser` object, `source_seq` unsigned integer array, `method` string, `scheme` string or null, `authority` string or null, `path` string, `headers` array, `body` object or null |
| `http.response` | `parser` object, `source_seq` unsigned integer array, `status` unsigned integer, `headers` array, `body` object or null |

`network` is `tcp` or `udp`. DNS `transport` is `udp` or `tcp`. DNS
`boundary` is `fake` or `system`. TLS `mode` is `runtime` or `relay`.
The `run.open.data.capture` object contains `profile` and
`payload_storage = "content_addressed"`; payload references are ordinary
`flow.data` records in the event segments.
Destination identity uses exactly one of `host` or `ip`, plus `port`; agents
must not infer a hostname from SNI when the destination is an IP. An action has
`type` equal to `route`, `direct`, or `reject`; `route` has an `outbound` and
`reject` has a `method`.

For a closed run, foreground shutdown drains tracked flows before
`run.close`. Treat a missing `flow.close`, a shutdown error, or a failed
`logs verify` result as incomplete evidence.

### Flow data

`flow.data.data` contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `direction` | enum | `client_to_remote` or `remote_to_client` |
| `boundary` | enum | `transport`, `tls_plaintext.runtime`, or `tls_plaintext.relay` |
| `original_bytes` | unsigned integer | Bytes observed before capture limits |
| `stored_bytes` | unsigned integer | Bytes persisted in the blob, or zero |
| `truncated` | boolean | Observation exceeded a configured limit |
| `blob` | object or null | Content-addressed payload reference |

Never infer plaintext from ports, SNI, or byte shape. Only a boundary beginning
with `tls_plaintext.` is plaintext evidence.

A non-null blob has:

| Field | Type | Constraint |
| --- | --- | --- |
| `algorithm` | string | `sha256` |
| `digest` | string | 64 lowercase hexadecimal characters |
| `path` | string | Relative path below the run's `blobs/` directory |
| `bytes` | unsigned integer | Stored content length |
| `media_type` | string | Media type, default `application/octet-stream` |

Canonicalize the joined path, prove it remains below `run_dir/blobs`, and
verify SHA-256 before consuming payload bytes. Never shell-evaluate a path.

### Errors

`run.error.data` and `tls.error.data` use stable `code` for control flow.
Messages are explanatory only. Error data always includes `phase` and
`retryable`; context remains structured. Do not branch on English text.

Relay TLS uses `tls_upstream_client_auth_required` when a verified upstream
requires a client certificate. Relay mode cannot forward the wrapped client's
identity; select runtime mode or disable decryption instead of weakening TLS.

### Derived HTTP

`http.request` and `http.response` are optional. The
`heimdall-http1` version `1` parser considers only the first complete HTTP/1
header per direction from explicit `tls_plaintext.*` events and buffers no more
than 64 KiB. Each record contains `source_seq`, the contributing plaintext
event sequence numbers. Resolve every number back to a `flow.data` event before
using the derived record. Their absence means no record was parsed; it does not
prove that a flow is not HTTP.

`Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` values are
always `[REDACTED]`. Configured exact-value payload redaction runs before this
parser. `body` is always null; inspect a permitted source blob only when the
task authorizes payload access. HTTP/2, invalid, incomplete, and oversized
headers produce no derived record.

## `heimdall.run/v1`

`run.json` is one JSON object with these required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `heimdall.run/v1` |
| `run_id` | UUIDv7 string | Run identity |
| `state` | enum | `starting`, `running`, `closing`, `closed`, or `failed` |
| `started_at` | RFC 3339 string | Start time |
| `closed_at` | RFC 3339 string or null | Finalization time |
| `command` | object | Executable, argv count, and optional redacted argv array |
| `policy` | string | Selected policy |
| `backend` | string | Actual interception backend |
| `capture` | object | Selected boundaries and limits |
| `segments` | object array | Sequence ranges, sizes, digests, finalization |
| `blobs` | object | Count and total bytes |
| `result` | object or null | Process and Heimdall outcome |

Do not read `run.json` once and assume it is immutable while `state` is not
`closed` or `failed`. Re-open it after `run.close` or use `logs tail --follow`.

By default `command.argv` is null. Agents use `command.executable` and
`command.argv_count` for correlation. There is no digest of unredacted argv
because low-entropy secrets could be guessed from it. A non-null `argv`
requires explicit capture and is still an array, never shell text. Treat it as
sensitive and never evaluate or print it without authority.

## Rotation and querying

For an active run, request rotation from its writer:

```bash
heimdall logs rotate --run "$run_id" --json
```

Never rename, truncate, or run external `copytruncate` against an active
segment. `run_not_active` means history was left unchanged.

Prefer the built-in stream across rotation:

```bash
heimdall logs tail --run "$run_id" --follow --jsonl |
  jq --unbuffered -c 'select(.kind == "run.error" or .kind == "tls.error")'
```

Use standard tools for arbitrary projection:

```bash
run_dir="$(heimdall logs path --run "$run_id" --json | jq -er '.run_dir')"
jq -c 'select(.kind == "policy.decision")' "$run_dir"/events-*.jsonl
jq -r 'select(.kind == "flow.close") |
  [.flow_id, .data.status, (.data.error_code // "-")] | @tsv' \
  "$run_dir"/events-*.jsonl
```

Before trusting a closed run, execute:

```bash
heimdall logs verify --run "$run_id" --json
```

Require valid bundled run/event schemas, segment and blob digests, continuous
committed sequence numbers, and a consistent final state. Preserve
an incomplete tail as evidence of a crash; do not manufacture a close event.
For a run orphaned in `starting`, `running`, or `closing`, preview and then
explicitly apply recovery only when the report is safe:

```bash
heimdall logs recover --run "$run_id" --json
heimdall logs recover --run "$run_id" --apply --json
```

Recovery refuses a live owner, immutable final states, complete invalid
records, and changed finalized segments. Applied recovery stores the original
manifest and discarded tail below the returned private `recovery_dir`.

## Retention safety

Rotation does not delete data. Use prune separately and preview it first:

```bash
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
```

Never prune an active run. Capture can contain credentials and personal data,
so do not upload, print, or retain payload blobs without explicit authority.
