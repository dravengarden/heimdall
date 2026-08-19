# Command workflows

## Inspect without mutation

```bash
heimdall agent
heimdall config path
heimdall config show
heimdall config validate --json
heimdall config explain --policy default --domain example.com --port 443 --json
heimdall config explain --policy default --network udp --domain example.com --port 443 --json
heimdall logs list --json
```

`agent` is the primary `heimdall.agent/v8` machine contract. Exit 0 means
ready, 1 means not ready, and 2 is CLI usage error. It never mutates state.
Require the foreground execution owner and `daemon_required = false`. There is
no persistent service or health endpoint.

`config show` prints source text. `config validate` applies the shared strict
schema. `config explain` evaluates one destination and returns the first rule
plus structured action; use `--network udp` and either `--domain` or `--ip` as
appropriate.

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
jq -r 'select(.kind == "flow.close") |
  [.flow_id, .data.status, .data.client_to_remote_bytes,
   .data.remote_to_client_bytes] | @tsv' "$run_dir"/events-*.jsonl
rg '"kind":"run.error"|"kind":"tls.error"' "$run_dir"
wc -l "$run_dir"/events-*.jsonl
heimdall logs verify --run "$run_id" --json
heimdall logs query --run "$run_id" --boundary tls_plaintext.relay --has-blob --jsonl
heimdall logs prune --max-total-bytes 1073741824 --keep-last 20 --json
```

For a live stream across writer-owned rotation:

```bash
heimdall logs tail --run "$run_id" --follow --jsonl |
  jq --unbuffered -c 'select(.kind == "run.error" or .kind == "flow.close")'
```

Do not rename, truncate, or `copytruncate` active segments.
Prune is a dry run unless `--apply` is explicit. Verify candidate paths and
reasons before applying it.

## Relay TLS

Only with authority to install local trust:

```bash
install -d -m 0700 "$HOME/.local/state/heimdall/tls"
heimdall tls init-ca --dir "$HOME/.local/state/heimdall/tls" --json
```

Trust only the reported `ca_cert`. Keep `ca_key` private, mode 0600, and owned
by the same user that runs Heimdall. No daemon is required for relay TLS.

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
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
```

Rotation never deletes. Preview prune before `--apply`, and never prune an
active run.

## Diagnose failures

1. Preserve `heimdall agent` JSON even when it exits 1.
2. Execute `actions.validate` as argv, not shell text.
3. Preview the same policy and destination with `config explain`.
4. If foreground setup fails, verify the exact sudoers binary path and
   `heimdall __setup-worker` authorization.
5. For runtime TLS setup failures, confirm a representative OpenSSL image was
   mapped before invocation and preserve the pre-exec error.
6. Reproduce with the smallest command that uses the same protocol and policy.

Do not equate config validity with connectivity. A real acceptance check must
exercise `heimdall run`.
