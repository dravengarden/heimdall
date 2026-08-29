# Agent-first event log design

Status: lifecycle, TCP/UDP metadata, bounded content-addressed payload blobs,
payload-aware queries, byte/age rotation, and integrity verification are
implemented. Correlated fake-DNS, policy-decision, OpenSSL runtime-observation,
relay ClientHello, and relay TLS handshake/error metadata are implemented.
Bounded provenance-linked HTTP/1 request/response header records are
implemented for explicit TLS plaintext. Strict low-cardinality run and
per-flow explanation documents are implemented without replacing JSONL as the
evidence source of truth.

The writer/control/finalization owner and offline log CLI run on Linux and
Darwin. The Apple-silicon `macos-explicit` backend emits cooperative TCP policy
and flow metadata, but no payload, DNS, TLS, or process-attribution evidence.
The future transparent backend has a separate native acceptance boundary.

This document defines the unified storage and CLI contract. The goals are direct Linux-tool usability, strict
machine discovery, bounded storage, and loss-aware rotation. The event log is
useful without a Web UI.

## Filesystem layout

User-owned runs live under `$XDG_STATE_HOME/heimdall/runs`, defaulting to
`~/.local/state/heimdall/runs`. Ephemeral control sockets live under
`$XDG_RUNTIME_DIR/heimdall`; they never live in the persistent log tree.

```text
runs/
  2026/08/18/
    0198.../                         # UUIDv7 run_id
      run.json                       # heimdall.run/v1
      events-000001.jsonl            # heimdall.event/v1 records
      events-000002.jsonl
      blobs/
        sha256/
          ab/cd/<full digest>
```

Directories are mode `0700` and files are mode `0600`. `run.json` and every
event contain a `run_id`, so moving a run directory does not change identity.
UUIDv7 provides standardized, time-ordered IDs without embedding host or user
identity.

The persistent path follows the XDG state definition for logs and history.
Sockets use the XDG runtime directory because it is private, local, and bound
to the login lifetime.

## JSONL rules

Every event segment is UTF-8 JSON Lines:

- one complete JSON object per physical line;
- every record ends in `\n`;
- no comments, blank lines, multiline values, NaN, or Infinity;
- object key order is not semantically significant;
- a record becomes visible only after the complete line is written;
- the writer uses one append operation per encoded record and never has two
  writers for one run;
- `seq` is strictly increasing and gap-free for records successfully committed
  by the writer;
- readers order by `seq`, not timestamp or file name.

Wall-clock timestamps use RFC 3339 UTC with microsecond precision. A separate
`monotonic_ns` orders durations within the run even if wall time changes.

## Event envelope

Every line has this stable envelope:

```json
{"schema":"heimdall.event/v1","run_id":"0198f82d-25a7-7b7c-9a84-582f2be76831","seq":42,"ts":"2026-08-18T07:31:22.123456Z","monotonic_ns":881234567,"kind":"flow.open","flow_id":"0198f82d-2c4b-76af-a654-344ca0360265","data":{"network":"tcp","source":{"cgroup_id":42},"destination":{"host":"example.com","port":443},"action":{"type":"route","outbound":"default"},"policy":"default","boundary":"transport"}}
```

| Field | Type | Required | Contract |
| --- | --- | --- | --- |
| `schema` | string | yes | Exactly `heimdall.event/v1` |
| `run_id` | UUIDv7 string | yes | Same value for every record in the run |
| `seq` | unsigned integer | yes | Starts at 1 and increases by one per committed record |
| `ts` | RFC 3339 string | yes | UTC wall time with `Z` |
| `monotonic_ns` | unsigned integer | yes | Nanoseconds since this run's monotonic origin |
| `kind` | string | yes | Closed v1 event-kind enum |
| `flow_id` | UUIDv7 string | by kind | Required for flow, TLS, payload, and protocol events |
| `pid` | unsigned integer | optional | Observed process ID; never used as durable identity |
| `data` | object | yes | Kind-specific object; unknown fields are rejected in v1 |

The checked-in JSON Schema is the normative field/type definition. This prose
defines lifecycle and security semantics. `heimdall logs schema --event v1`
prints that exact schema as one JSON document without network access.

## Run manifest

`run.json` is atomically replaced after state changes and finalized after the
last event fsync. Its contract is `heimdall.run/v1`.

Required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Exactly `heimdall.run/v1` |
| `run_id` | UUIDv7 string | Run identity |
| `state` | enum | `starting`, `running`, `closing`, `closed`, or `failed` |
| `started_at` | RFC 3339 string | Creation time |
| `closed_at` | RFC 3339 string or null | Finalization time |
| `command` | object | Executable, argv count, and optional redacted argv array |
| `policy` | string | Selected policy name |
| `backend` | string | Actual interception backend |
| `capture` | object | Event profile, payload allowlists/redaction summary, `heimdall.event/v1`, blob/flow limits, and segment rotation limits |
| `segments` | object array | File, first/last sequence, bytes, SHA-256, final state |
| `blobs` | object | Count and total stored bytes |
| `result` | object or null | Exit status, signal, Heimdall error code, completeness |

Full argv is not stored by default because credentials and signed URLs often
appear in command arguments. The default command object contains `executable`,
`argv_count`, and a null `argv`. A digest of unredacted argv is also forbidden
because it can disclose low-entropy secrets through guessing. V1 does not
support argv or environment capture. `capture.redact_env` reads values only to
mask matching payload bytes; it never persists those values as metadata.

## Event kinds

The v1 schema reserves the kinds below. The current writer emits run lifecycle,
fake-DNS, policy-decision, TCP/UDP flow, payload-reference, `tls.runtime`, relay
`tls.client_hello`, relay `tls.handshake`/`tls.error`, and derived HTTP/1
request/response records. New meanings require a new schema version; optional
fields cannot reinterpret an existing kind.

### Run lifecycle

- `run.open`: normalized policy, backend, capture boundary, and schema versions.
- `run.ready`: interception and all selected inspection boundaries are active.
- `run.exec`: child PID, executable, and argv count; full argv remains opt-in.
- `run.warning`: stable `code`, message, and structured context.
- `run.error`: stable `code`, phase, retryability, and structured context.
- `run.close`: child result, descendant cleanup, and completeness summary.

### DNS and policy

- `dns.query`: exchange UUID, transport, question array, and policy.
- `dns.answer`: matching exchange UUID, rcode, answers, fake boundary, and
  latency.
- `policy.decision`: source boundary, policy, network, destination identity,
  matched rule or final action, and selected action. Linux identifies
  `{cgroup_id}`; `macos-explicit` identifies
  `{backend:"macos-explicit",scope:"cooperative_environment"}`. The latter
  proves only that a client reached the cooperative listener, not which process
  originated every socket.

### Flows

- `flow.open`: network, the same platform-specific source metadata,
  destination, and selected action.
- `flow.data`: direction, observation boundary, original length, stored length,
  truncation state, and optional blob reference.
- `flow.close`: byte counters, duration, status, and error code when present.

During shutdown, the foreground owner first prevents new flows, closes
its UDP sessions, and waits up to two seconds for tracked event flows to drain
through `flow.close`. Only then does `heimdall run` append `run.close` and
finalize the manifest. A timeout is recorded as incomplete drain evidence,
never silently treated as complete.

`flow.data.data.boundary` is one of:

- `transport`: opaque TCP bytes or UDP datagram payload;
- `tls_plaintext.runtime`: bytes observed at a supported TLS-library API;
- `tls_plaintext.relay`: bytes observed after relay TLS termination.

The boundary is evidence, not an inference. A TLS-looking transport payload is
still `transport`.

### TLS metadata

- `tls.runtime`: OpenSSL API family, direction, observed/reported byte counts,
  truncation, PID, and the explicit `tls_plaintext.runtime` boundary.
- `tls.client_hello`: SNI and offered ALPN from rustls' parsed relay
  ClientHello. `min_version` and `max_version` are currently null because the
  public parser API does not expose the offered version list;
  `parser_status=parsed_versions_unavailable` makes that limit explicit.
- `tls.handshake`: mode, negotiated version/cipher/ALPN, peer identity result,
  trust boundary, and latency.
- `tls.error`: mode, stable code, phase, and peer-verification evidence.
  Relay certificate failures use `tls_upstream_certificate_invalid` during
  `upstream_handshake` or `tls_downstream_certificate_rejected` during
  `downstream_handshake`. Some clients send no certificate alert and close
  without `close_notify`; that is reported separately as
  `tls_downstream_closed_without_close_notify` and must not be presented as a
  proven trust failure without the wrapped command's stderr/exit evidence.

No key material, session secrets, or private CA content is ever logged.

### Derived protocols

- `http.request`
- `http.response`

These records are optional derived evidence from the first complete HTTP/1
header block in each direction of an explicitly captured `tls_plaintext.*`
flow. The parser buffers at most 64 KiB per direction, emits no record for
invalid, incomplete, oversized, or non-HTTP/1 input, and does not parse HTTP/2.
Each record carries `parser={name:"heimdall-http1",version:"1"}` and
`source_seq`, the exact plaintext event sequence numbers that contributed to
the header. Absence means “not parsed,” not “not HTTP.”

`Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` values are
always replaced with `[REDACTED]` in derived headers. Other header values are
derived from payload bytes after configured exact-value redaction. `body` is
always null; retained payload remains governed by the blob allowlist,
redaction, and size limits above.

## Payload blobs

Binary and large plaintext payloads are never embedded as base64 in JSONL.
`flow.data.data.blob` has this shape:

```json
{
  "algorithm": "sha256",
  "digest": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "path": "blobs/sha256/ab/cd/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "bytes": 517,
  "media_type": "application/octet-stream"
}
```

`path` is relative to the run directory and MUST resolve below `blobs/` after
canonicalization. Identical bytes in one run share a blob. Publication uses a
private temporary file and an atomic same-filesystem link, so a failed write
never publishes a partial digest path. Readers verify the digest before
trusting content. Compression, if later added, gets explicit stored/content
sizes and encoding fields; it never changes digest semantics. Observed reads
are coalesced per flow and direction into blocks bounded by the configured
`block_max_bytes`. Literal redaction may retain at most the longest configured
value minus one byte per direction so split matches are masked. A block flushes
when it reaches the size bound, after `flush_interval_ms`, or when the flow
closes. `flow.data.data.block` records a one-based per-direction index, both
configured bounds, and `flush_reason=size|interval|close`.

Capture profiles:

- `metadata`: no payload blobs; lengths, policy, DNS, TLS metadata, and errors
  remain available;
- `payload`: bounded opaque or plaintext blobs according to the TLS boundary;
- `off` is reserved in the schema; current `capture.mode = off` maps to the
  `metadata` profile so agent-readable flow evidence remains available.

The current default is `metadata`. Plaintext payload capture requires explicit
configuration because it may contain credentials or personal data.
The run manifest records `allowed_boundaries`, `allowed_directions`, and only
the redaction source/value count/replacement method. It never records secret
values. It also records the block size and flush interval required to interpret
capture latency.

## Rotation

Each run owns its writer. Rotation closes and fsyncs the current segment,
records its sequence range and digest in `run.json`, then atomically creates the
next numbered segment. A record is never split across segments.

Automatic rotation supports `segment_max_bytes` and `segment_max_age_ms`.
Age is measured with the run's monotonic clock. The limits are recorded in
`run.json`; the next record starts a new segment when either limit is reached.

One oversize event may exceed `segment_max_bytes`; it remains intact and the
next event starts a new segment. Payload blobs have independent per-flow and
per-run limits.

Manual rotation is:

```bash
heimdall logs rotate --run <run_id> --json
```

For an active run, the command sends a versioned request to the session's mode
`0600` Unix socket under `$XDG_RUNTIME_DIR/heimdall`. The writer performs the
same close/open transaction and returns the finalized segment metadata. An
inactive run returns `run_not_active` and does not rewrite history.

External rename or `copytruncate` rotation is unsupported. Only the active
writer knows the committed sequence and manifest transaction, and copying then
truncating has an inherent interval in which data can be lost.

## Retention

Rotation preserves data; pruning deletes it. They are separate commands.

```bash
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
heimdall logs prune --max-total-bytes 1073741824 --keep-last 20 --json
```

Prune defaults to dry-run unless the explicit `--apply` option is present.
It never removes active runs, follows no symlinks, and deletes a complete run
directory as one unit. Selection combines maximum age, maximum total bytes,
and minimum runs to keep. The JSON result lists every candidate, reason, byte
count, projected total, and whether the requested limit can be satisfied
without deleting active or protected runs.

Retention is never automatic. An operator or agent explicitly runs preview and
apply as the invoking user at a workflow boundary. Heimdall starts no timer or
daemon. Preserve the machine-readable result as deletion evidence and verify
the runs that remain. `limit_satisfied=false` is expected when active or
`--keep-last`-protected runs alone exceed the requested byte limit.

## Agent-first CLI

All discovery commands return one JSON document. Only `tail --jsonl` is a
stream.

```text
heimdall logs schema --event v1
heimdall logs schema --run v1
heimdall logs schema --summary v1
heimdall logs schema --flow v1
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
heimdall logs flow --run RUN_ID --flow FLOW_ID --json
heimdall logs path --run RUN_ID --json
heimdall logs query --run RUN_ID [filters] --jsonl
heimdall logs tail --run RUN_ID [--follow] --jsonl
heimdall logs rotate --run RUN_ID --json
heimdall logs verify --run RUN_ID --json
heimdall logs recover --run RUN_ID [--apply] --json
heimdall logs prune ... --json
```

`summary` returns exactly one `heimdall.logs.summary/v1` document. Its
low-cardinality fields aggregate sequence continuity, event kinds, unique
opened/closed/active flows, network/status/failure-code counts, durations,
bytes, capture truncation and boundaries, DNS, policy, TLS, HTTP, run errors,
segments, and blobs. It may summarize a live incomplete run. It does not
authenticate evidence; use `verify` for schema, digest, sequence, and blob
integrity. `logs schema --summary v1` exports its strict JSON Schema Draft
2020-12 contract offline.

`flow` returns exactly one `heimdall.logs.flow/v1` document for an exact
run/flow pair. It contains the run and flow completion states, selected
transport metadata, fixed capture counters by direction and boundary, actual
plaintext observation, TLS/HTTP counters, error evidence, and argv-safe
`query`/`verify` actions. It never embeds payload bytes, HTTP headers, or SNI.
`capture.plaintext.observed` becomes true only when a selected `flow.data`
record reports non-zero original bytes at a `tls_plaintext.*` boundary; a
configured decrypt mode or transport boundary alone is not proof. Error-code
counts are evidence-record counts, so one failure may appear once in
`tls.error.data.code` and again in its correlated
`flow.close.data.error_code`. The document is an index into the evidence, not
an integrity result; run its returned `actions.verify` before an integrity
claim. `logs schema --flow v1` exports the strict contract offline.

Contract rules:

- exit `0`: requested operation completed;
- exit `1`: operational failure represented by a stable code;
- exit `2`: CLI usage failure;
- stdout contains only the selected data contract;
- progress and human diagnostics go to stderr;
- every path in JSON is absolute unless explicitly named `relative_path`;
- timestamps and byte counts are never localized;
- filters use repeated flags, not a query-language string;
- `--follow` follows new segments and stops after `run.close` or `run.error`.

Query filters are `--kind`, `--flow`, `--since-seq`, `--until-seq`, repeated
`--direction`, repeated `--boundary`, repeated `--error-code`, and
`--has-blob[=true|false]`. `--error-code` matches stable codes stored in either
`data.code` or `data.error_code`. This deliberately does not invent a second
general-purpose query language; agents can use `jq` for arbitrary projection.

## Standard Linux-tool recipes

Resolve a run path without guessing XDG values:

```bash
run_dir="$(heimdall logs path --run "$run_id" --json | jq -er '.run_dir')"
```

List errors:

```bash
jq -c 'select(.kind == "run.error" or .kind == "tls.error")' \
  "$run_dir"/events-*.jsonl
```

Summarize flow outcomes:

```bash
jq -r 'select(.kind == "flow.close") |
  [.flow_id, .data.network, .data.status, (.data.error_code // "-")] | @tsv' \
  "$run_dir"/events-*.jsonl
```

Explain one selected flow without reading payload bytes:

```bash
heimdall logs flow --run "$run_id" --flow "$flow_id" --json |
  jq '{transport, plaintext: .capture.plaintext, tls, http, errors, actions}'
```

Find flows with captured TLS plaintext:

```bash
jq -r 'select(.kind == "flow.data" and
  (.data.boundary | startswith("tls_plaintext."))) | .flow_id' \
  "$run_dir"/events-*.jsonl | sort -u
```

Inspect derived HTTP/1 metadata with its source evidence:

```bash
jq -c 'select(.kind == "http.request" or .kind == "http.response") |
  {seq, flow_id, source_seq: .data.source_seq,
   method: .data.method, authority: .data.authority,
   path: .data.path, status: .data.status}' \
  "$run_dir"/events-*.jsonl
```

Verify and read one payload:

```bash
relative_path="$(jq -r 'select(.kind == "flow.data" and .data.blob) |
  .data.blob.path' "$run_dir"/events-*.jsonl | head -n 1)"
sha256sum "$run_dir/$relative_path"
od -An -tx1 -N 64 "$run_dir/$relative_path"
```

Follow safely across rotation:

```bash
heimdall logs tail --run "$run_id" --follow --jsonl |
  jq --unbuffered -c 'select(.kind == "policy.decision" or
    .kind == "run.error")'
```

Direct `tail -F events-*.jsonl` is acceptable for a fixed segment set but does
not reliably discover future numbered files. The Heimdall tail command exists
to bridge rotation while preserving the same raw event objects.

## Integrity and failure semantics

- A finalized segment has first/last sequence, byte count, and SHA-256 in the
  manifest.
- `heimdall logs verify` checks JSON syntax, schema, run IDs, sequence
  continuity, segment digests, blob paths, blob digests, and final-state
  consistency.
- Payload publication never silently downgrades. An affected flow fails with
  `event_store_full`, `event_store_permission_denied`, or `event_failed`; no
  partial digest path is published.
- Policy evidence is committed before the selected network action. Fake-DNS
  does not answer a query when its query/answer evidence cannot be committed,
  so a successful path never silently omits these decision records.
- A crash may leave only the last segment unfinalized. `logs recover` previews
  the last committed prefix and incomplete tail. With explicit `--apply`, it
  preserves the original manifest and discarded bytes below `recovery/`,
  finalizes that prefix as failed/incomplete, and never invents a close event.
  Complete invalid records or changed finalized segments are not recoverable.
- Payload boundary/direction allowlists are evaluated before capture. Exact
  secret values named through `capture.redact_env` are masked across observed
  read boundaries before hashing or blob creation. This literal mechanism does
  not cover encoded or transformed variants, so capture still requires
  authority to retain all remaining bytes.

## External standards

The design uses [JSON as defined by RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html),
[RFC 3339 timestamps](https://www.rfc-editor.org/rfc/rfc3339.html),
[UUIDv7 from RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html),
[XDG state/runtime directories](https://specifications.freedesktop.org/basedir-spec/latest/),
and [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12).
These choices keep the format inspectable with ordinary tools and independently
validatable without importing Heimdall code. The upstream
[`logrotate` manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)
also documents the copy/truncate loss interval that writer-owned rotation
avoids.
