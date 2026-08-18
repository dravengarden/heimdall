# Agent-first event log design

Status: Phase 1 implemented for run lifecycle and TCP/UDP flow metadata. Payload
blobs, TLS/HTTP events, and full daemonless ownership remain in progress.

This document defines the storage and CLI contract that replaces per-flow
`heimdall.capture/v1` files. The goals are direct Linux-tool usability, strict
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
| `capture` | object | Metadata/payload/TLS boundaries and truncation limits |
| `segments` | object array | File, first/last sequence, bytes, SHA-256, final state |
| `blobs` | object | Count and total stored bytes |
| `result` | object or null | Exit status, signal, Heimdall error code, completeness |

Full argv is not stored by default because credentials and signed URLs often
appear in command arguments. The default command object contains `executable`,
`argv_count`, and a null `argv`. A digest of unredacted argv is also forbidden
because it can disclose low-entropy secrets through guessing. If explicit argv
capture is enabled, `argv` remains an array rather than shell text and
configured redaction runs before persistence. Environment values are not
stored by default. Optional environment capture is a separate redacted
feature, not part of v1.

## Event kinds

The v1 enum is intentionally small. New meanings require a new schema version;
optional fields cannot reinterpret an existing kind.

### Run lifecycle

- `run.open`: normalized policy, backend, capture boundary, and schema versions.
- `run.ready`: interception and all selected inspection boundaries are active.
- `run.exec`: child PID, executable, and argv count; full argv remains opt-in.
- `run.warning`: stable `code`, message, and structured context.
- `run.error`: stable `code`, phase, retryability, and structured context.
- `run.close`: child result, descendant cleanup, and completeness summary.

### DNS and policy

- `dns.query`: transport, query name, type, and policy.
- `dns.answer`: rcode, answers, fake/system boundary, and latency.
- `policy.decision`: network, destination identity, matched rule, and action.

### Flows

- `flow.open`: network, source metadata, destination, and selected action.
- `flow.data`: direction, observation boundary, original length, stored length,
  truncation state, and optional blob reference.
- `flow.close`: byte counters, duration, status, and error code when present.

During Phase 1 deregistration, the daemon first prevents new flows for the run,
closes its UDP sessions, and drains every tracked TCP/UDP flow through
`flow.close`. Only then may `heimdall run` append `run.close` and finalize the
manifest. The drain is bounded to five seconds; a timeout is an explicit
deregistration error rather than silent evidence loss.

`flow.data.data.boundary` is one of:

- `transport`: opaque TCP bytes or UDP datagram payload;
- `tls_plaintext.runtime`: bytes observed at a supported TLS-library API;
- `tls_plaintext.relay`: bytes observed after relay TLS termination.

The boundary is evidence, not an inference. A TLS-looking transport payload is
still `transport`.

### TLS metadata

- `tls.client_hello`: SNI, offered ALPN, version range, and parser status.
- `tls.handshake`: mode, negotiated version/cipher/ALPN, peer identity result,
  trust boundary, and latency.
- `tls.error`: mode, stable code, phase, and peer-verification evidence.

No key material, session secrets, or private CA content is ever logged.

### Derived protocols

- `http.request`
- `http.response`

These records are optional derived evidence. They carry `source_seq` values
pointing to the plaintext events from which they were parsed and a parser
version. Absence means “not parsed,” not “not HTTP.” Header values and bodies
follow the same capture/redaction limits as payload blobs.

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
canonicalization. Identical bytes in one run may share a blob. Readers verify
the digest before trusting content. Compression, if later added, gets explicit
stored/content sizes and encoding fields; it never changes digest semantics.
The writer coalesces consecutive bytes from the same flow and direction into
bounded blocks before creating blobs, so a byte stream does not create one file
per relay read. Block size and maximum flush latency are explicit capture
settings and appear in `run.json`.

Capture profiles:

- `metadata`: no payload blobs; lengths, policy, DNS, TLS metadata, and errors
  remain available;
- `payload`: bounded opaque or plaintext blobs according to the TLS boundary;
- `off`: only minimal run lifecycle and fatal-error evidence.

The default is `metadata`. Plaintext payload capture requires explicit
configuration because it may contain credentials or personal data.

## Rotation

Each run owns its writer. Rotation closes and fsyncs the current segment,
records its sequence range and digest in `run.json`, then atomically creates the
next numbered segment. A record is never split across segments.

Phase 1 automatic rotation supports:

- `segment_max_bytes`, measured before adding the next record;

Age-based rotation is planned and will be measured with monotonic time.

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
```

Prune defaults to dry-run unless the explicit `--apply` option is present.
It never removes active runs, follows no symlinks, and deletes a complete run
directory as one unit. Phase 1 selection combines maximum age and minimum runs
to keep; maximum-total-bytes retention is planned. The JSON result lists every
candidate, reason, and byte count before deletion.

Automatic retention is off by default. If enabled, it runs only at the end or
start of a foreground Heimdall command; it does not require a timer or daemon.

## Agent-first CLI

All discovery commands return one JSON document. Only `tail --jsonl` is a
stream.

```text
heimdall logs schema --event v1
heimdall logs schema --run v1
heimdall logs list --json
heimdall logs path --run RUN_ID --json
heimdall logs query --run RUN_ID [filters] --jsonl
heimdall logs tail --run RUN_ID [--follow] --jsonl
heimdall logs rotate --run RUN_ID --json
heimdall logs verify --run RUN_ID --json
heimdall logs prune ... --json
```

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

Phase 1 query filters are `--kind`, `--flow`, `--since-seq`, and `--until-seq`.
Direction, boundary, error-code, and blob-presence filters arrive with payload
events. This deliberately does not invent a second general-purpose query
language; agents can use `jq` for arbitrary projection.

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

Find flows with captured TLS plaintext:

```bash
jq -r 'select(.kind == "flow.data" and
  (.data.boundary | startswith("tls_plaintext."))) | .flow_id' \
  "$run_dir"/events-*.jsonl | sort -u
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
- If storage becomes unavailable, metadata or payload capture never silently
  downgrades. The configured policy chooses `terminate_run` or
  `continue_without_payload`; the latter emits a durable warning before the
  downgrade whenever any writable segment remains.
- A crash may leave only the last segment unfinalized. Verification reports
  the last complete line and `incomplete_tail`; it never invents a close event.
- Secrets are not redacted after writing. Redaction and header/body allowlists
  run before blob creation so forbidden bytes never reach disk.

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
