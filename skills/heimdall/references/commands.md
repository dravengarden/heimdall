# Command workflows

## Contents

- [Inspect without mutation](#inspect-without-mutation)
- [Run through a policy](#run-through-a-policy)
- [Inspect JSONL with Linux tools](#inspect-jsonl-with-linux-tools)
- [Relay TLS](#relay-tls)
- [Runtime TLS](#runtime-tls)
- [Rotate and retain](#rotate-and-retain)
- [Diagnose failures](#diagnose-failures)

## Inspect without mutation

```bash
heimdall agent
heimdall config schema --version v1
heimdall config example --format toml
heimdall config path
heimdall config show
heimdall config validate --json
heimdall config explain --policy default --domain example.com --port 443 --json
heimdall config explain --policy default --network udp --domain example.com --port 443 --json
heimdall logs schema --event v1
heimdall logs schema --run v1
heimdall logs schema --summary v1
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
```

`agent` is the primary `heimdall.agent/v8` machine contract. Exit 0 means
ready, 1 means not ready, and 2 is CLI usage error. It never mutates state.
Require the foreground execution owner and `daemon_required = false`. There is
no persistent service or health endpoint.
When capture is on, require
`config.capture.redaction_values_ready = true`, then inspect its explicit
boundary/direction allowlists before using `actions.execute_prefix`.

`config schema` prints the generated structural contract offline. `config
example` prints the same complete starter used by `init` without writing.
`config show` prints source text. `config validate` adds cross-reference and
capability checks. `config explain` evaluates one destination and returns the
first rule plus structured action; use `--network udp` and either `--domain`
or `--ip` as appropriate.

The three `logs schema` actions export the strict event, manifest, and summary
contracts without network access. Validate stored or generated documents
against those schemas instead of copying field lists from prose.

## Run through a policy

```bash
heimdall agent --policy default
heimdall run --policy default -- curl https://example.com
```

The command may re-enter through `systemd-run --user --scope`. The resolved
global config path and exact argv survive re-entry. An authorized setup helper
attaches one transient cgroup and drops privilege before the child starts.
Every mode keeps that unprivileged helper only until the run exits so an
unexpected owner death can kill the command cgroup before links disappear.
The foreground process owns relay/DNS listeners, maps, links, and logs until
the complete descendant tree exits.

For two independent runs, execute them normally in parallel; do not share a
manual relay. Verify `capabilities.lifecycle.concurrent_runs_isolated`
before depending on this boundary.

## Inspect JSONL with Linux tools

Discover the path first:

```bash
run_dir="$(heimdall logs path --run "$run_id" --json | jq -er '.run_dir')"
```

Then query append-only segments directly:

```bash
jq -c 'select(.kind == "policy.decision")' "$run_dir"/events-*.jsonl
jq -s 'map(select(.kind == "dns.query" or .kind == "dns.answer"))
  | group_by(.data.exchange_id)' "$run_dir"/events-*.jsonl
jq -c 'select(.kind == "tls.runtime") |
  [.pid, .data.api_family, .data.direction, .data.observed_bytes]' \
  "$run_dir"/events-*.jsonl
jq -c 'select(.kind == "tls.client_hello") |
  [.flow_id, .data.sni, .data.alpn_offered, .data.parser_status]' \
  "$run_dir"/events-*.jsonl
jq -c 'select(.kind == "http.request" or .kind == "http.response") |
  {seq, flow_id, source_seq: .data.source_seq,
   method: .data.method, authority: .data.authority,
   path: .data.path, status: .data.status}' \
  "$run_dir"/events-*.jsonl
jq -r 'select(.kind == "flow.close") |
  [.flow_id, .data.status, .data.client_to_remote_bytes,
   .data.remote_to_client_bytes] | @tsv' "$run_dir"/events-*.jsonl
rg '"kind":"run.error"|"kind":"tls.error"' "$run_dir"
wc -l "$run_dir"/events-*.jsonl
heimdall logs verify --run "$run_id" --json
heimdall logs recover --run "$run_id" --json
heimdall logs query --run "$run_id" --boundary tls_plaintext.relay --has-blob --jsonl
heimdall logs prune --max-total-bytes 1073741824 --keep-last 20 --json
```

Start with `logs summary` when choosing what to inspect. Its single
`heimdall.logs.summary/v1` document reports sequence loss/order, unique
opened/closed/active flows, network/status/failure-code counts, durations,
bytes, capture truncation/boundaries, protocol counters, segments, and blobs.
It can describe a live incomplete run and does not replace `logs verify`.

For a closed run expected to be clean, use a bounded gate before selecting
detailed evidence:

```bash
heimdall logs summary --run "$run_id" --json | jq -e '
  .contract == "heimdall.logs.summary/v1"
  and .state == "closed" and .complete
  and .sequence.contiguous
  and .flows.active == 0
  and .error_events.total == 0
' >/dev/null
```

`--has-blob` selects only records with a non-null content-addressed blob
reference. Before reading one, run `logs verify`, resolve its path with
`realpath`, prove it remains below the discovered `run_dir/blobs`, and compare
both `stat -c '%s'` and `sha256sum` with the reference. The complete
non-disclosing recipe is in [events.md](events.md#flow-data).

For a live stream across writer-owned rotation:

```bash
heimdall logs tail --run "$run_id" --follow --jsonl |
  jq --unbuffered -c 'select(.kind == "run.error" or .kind == "flow.close")'
```

Do not rename, truncate, or `copytruncate` active segments. Recover and prune
are dry runs unless `--apply` is explicit. Recovery is only for an orphaned,
non-final run; it preserves removed evidence and refuses complete corruption.
Verify candidate paths and reasons before applying either operation.

## Relay TLS

Only with authority to install local trust:

```bash
install -d -m 0700 "$HOME/.local/state/heimdall/tls"
heimdall tls init-ca --dir "$HOME/.local/state/heimdall/tls" --json
```

Compare the returned `ca_cert_sha256` with
`agent.config.decrypt.ca_cert_sha256`, then trust only the reported `ca_cert`
in the explicitly wrapped client. Prefer curl `--cacert`, Git
`-c http.sslCAInfo=...`, `NODE_EXTRA_CA_CERTS`, or `REQUESTS_CA_BUNDLE` over
machine-wide trust. Keep `ca_key` private, mode 0600, and owned by the same user
that runs Heimdall. No daemon is required for relay TLS.

## Runtime TLS

Only when the client uses a reported OpenSSL API:

```bash
heimdall agent | jq -e '
  .ready and (.execution.daemon_required | not) and
  .execution.owner == "heimdall-run" and
  .capabilities.decrypt.runtime_discovery == "loaded_images_at_run_start"'
heimdall run -- curl https://example.com
```

Runtime mode discovers loaded OpenSSL images at run startup. Keep a
representative image mapped before invoking the run. Do not infer coverage for
Go TLS, rustls, BoringSSL, JVM TLS, later-loaded images, or static/stripped
implementations.

## Rotate and retain

```bash
heimdall logs rotate --run "$run_id" --json
heimdall logs recover --run "$run_id" --json
heimdall logs recover --run "$run_id" --apply --json
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
```

Rotation never deletes. Preview recover and prune before `--apply`; neither
operation mutates an active run. Run prune as the invoking user, preserve its
JSON result as deletion evidence, and verify the retained runs. A false
`limit_satisfied` means protected runs alone exceed the requested byte limit.

## Diagnose failures

1. Preserve `heimdall agent` JSON even when it exits 1.
2. Execute `actions.validate` as argv, not shell text.
3. Preview the same policy and destination with `config explain`.
4. If foreground setup fails, verify the exact sudoers binary path and
   `heimdall __setup-worker` authorization.
5. For runtime TLS setup failures, confirm a representative OpenSSL image was
   mapped before invocation and preserve the pre-exec error.
6. For relay TLS, distinguish `tls_upstream_certificate_invalid` from
   `tls_downstream_certificate_rejected` and
   `tls_downstream_closed_without_close_notify`; preserve child stderr for an
   unclean close and never disable upstream verification.
7. Reproduce with the smallest command that uses the same protocol and policy.

Do not equate config validity with connectivity. A real acceptance check must
exercise `heimdall run`.
