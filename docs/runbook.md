# Runbook

## Build

Build eBPF first because its ELF is embedded in the single userspace binary.

```bash
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c just verify
```

Run the real kernel acceptance after changes to eBPF, cgroups, DNS, relay,
capture, TLS, setup privilege, or lifecycle behavior:

```bash
nix develop -c just test-vm
```

This runs the same static release binary and full cgroup v2/eBPF suite in
disposable NixOS guests on the nixpkgs current kernel and Linux 6.6 LTS. Both
cover dual-stack TCP/UDP, fake and system DNS, SOCKS5, QUIC, common runtime
clients, concurrent runs, runtime and relay TLS, capture, rotation, recovery,
signals, authorization failure, parent-death cleanup, and link cleanup.

Build both generic static archives, reject incorrect architecture or dynamic
linkage, exercise the aarch64 CLI under emulation, and run native x86_64
install, upgrade, and rollback acceptance:

```bash
nix develop -c just test-package
```

The `Linux CI` workflow runs the same source, package, and per-kernel gates on
every pull request and `main` push. The tagged release workflow reruns source,
both real-eBPF kernels, and package checks before attestation or publication;
Pages success alone is not release evidence.

The disposable NixOS VM proves fake/system DNS, SOCKS5 and direct TCP/UDP,
IPv4/IPv6, HTTP/3, static
and dynamic clients, descendants, exit/signal status, two concurrent isolated
runs, event rotation, relay TLS, fail-closed upstream errors, and return to the
pre-run BPF-link baseline. It also kills a live foreground owner and proves the
unprivileged helper removes the workload cgroup and BPF links.

## Install the daemonless path

For a tagged release, follow [install.md](install.md). For a source build,
install one executable:

```bash
sudo install -Dm755 target/release/heimdall /usr/local/bin/heimdall
/usr/local/bin/heimdall init
```

The normal Linux backend needs root only while attaching per-run eBPF. Grant
the invoking user access to the exact hidden setup command, not to arbitrary
Heimdall arguments and not to a shell. Replace `USERNAME` and validate the
result with `visudo`:

```sudoers
USERNAME ALL=(root) NOPASSWD: /usr/local/bin/heimdall __setup-worker
```

```bash
sudo chmod 0440 /etc/sudoers.d/heimdall
sudo visudo -cf /etc/sudoers.d/heimdall
```

`heimdall run` invokes this worker once over an inherited Unix socket. The
worker transfers map/link FDs, irrevocably drops to the caller, and remains as
a session-scoped parent-death guard. Runtime TLS also relies on it to retain
Aya probe state. An unexpected owner exit makes the helper kill and remove only
that run's cgroup. Do not install file capabilities or setuid on the complete
binary.

No Heimdall service exists or is required for any decrypt mode.

## Smoke test

Run as the ordinary authorized user:

```bash
heimdall config validate --json
heimdall agent | jq '{ready, execution, decision}'
heimdall run -- curl -fsS https://example.com
heimdall logs list --json
```

The wrapped command's immediate exit or signal status is Heimdall's status.
SIGHUP, SIGINT, SIGQUIT, and SIGTERM addressed to the foreground owner are
forwarded to the immediate child; Heimdall remains alive to finalize evidence
and keeps interception active until every descendant leaves the command cgroup.
Setup authorization is non-interactive and fails before child execution when
the exact sudoers rule is absent.

## Agent contract

`heimdall agent [--policy NAME]` is read-only and prints exactly one JSON value.
Exit 0 means ready, 1 means the document contains a repairable reason, and 2 is
CLI usage failure. The current contract is `heimdall.agent/v8`.

The execution section is the ownership decision that automation must use (the
following is an excerpt):

```json
{
  "contract": "heimdall.agent/v8",
  "ready": true,
  "execution": {
    "backend": "linux-ebpf-foreground",
    "owner": "heimdall-run",
    "privilege_setup": "sudo-then-unprivileged-session-helper",
    "daemon_required": false,
    "web_ui_required": false
  }
}
```

With `decrypt.mode = "runtime"`, the same foreground backend uses the setup
helper to discover and attach already loaded OpenSSL images. A
missing representative image fails before the wrapped command starts.

Treat every `actions.*` command as an argv array; never concatenate or
shell-evaluate it. Consumers may rely on existing v8 field semantics and must
ignore additive unknown fields. Renaming or changing an existing semantic
requires a new contract version.
`actions.config_schema` and `actions.config_example_toml` are read-only and do
not require a valid or discoverable config file.

Before execution, inspect:

- `config.valid`, normalized capture/decrypt values, capture allowlists,
  redaction-value readiness, and stable diagnostics;
- `execution.backend`, `daemon_required`, and `privilege_setup`;
- `decision` for the selected policy and terminal TCP/UDP actions;
- per-family `capabilities.udp` instead of aggregate booleans;
- protocol-specific `runtime_acceptance` and `cli_acceptance` evidence;
- `capabilities.lifecycle.foreground_modes` and resource ownership.

## Event logs for agents

Every initialized run writes a user-owned manifest and append-only JSONL below
`$XDG_STATE_HOME/heimdall/runs` (default
`~/.local/state/heimdall/runs`). The files are the source of truth; no Web UI
or database is required.

Discover schemas and paths instead of hard-coding fields:

```bash
heimdall logs schema --event v1
heimdall logs schema --run v1
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
heimdall logs path --run RUN_ID --json
```

Query with the CLI or ordinary Linux tools:

```bash
heimdall logs query --run RUN_ID --kind flow.close --jsonl
heimdall logs tail --run RUN_ID --follow --jsonl
jq -c 'select(.kind == "flow.close" and .data.client_to_remote_bytes > 0)' \
  ~/.local/state/heimdall/runs/RUN_ID/events-*.jsonl
jq -c 'select(.kind == "http.request" or .kind == "http.response") |
  {seq, source_seq: .data.source_seq, method: .data.method,
   authority: .data.authority, path: .data.path, status: .data.status}' \
  ~/.local/state/heimdall/runs/RUN_ID/events-*.jsonl
rg '"kind":"run.error"' ~/.local/state/heimdall/runs/RUN_ID
```

`logs summary` emits one `heimdall.logs.summary/v1` document with sequence
continuity, active/closed flow counts, low-cardinality failure codes, byte and
capture-truncation totals, and DNS/policy/TLS/HTTP counters. It is an
operational aggregation, not a substitute for `logs verify`, which validates
schemas, segment digests, sequences, and referenced blobs.

Derived HTTP records contain only the first bounded HTTP/1 header per
direction from explicit TLS plaintext. Resolve `source_seq` before trusting
them; common credential headers are masked and `body` is always null.

Rotation is writer-owned and never deletes data:

```bash
heimdall logs rotate --run RUN_ID --json
heimdall logs verify --run RUN_ID --json
heimdall logs recover --run RUN_ID --json
heimdall logs recover --run RUN_ID --apply --json
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
```

Preview recover and prune before `--apply`. Recovery rejects active and already
finalized runs, preserves the original manifest and discarded tail, and marks
an orphaned run failed/incomplete without adding a synthetic close event. Do
not use `copytruncate` on an active segment. Retention is explicit: run preview
and apply as the same invoking user at a workflow boundary. Heimdall starts no
timer or daemon, never selects active runs, and may report
`limit_satisfied=false` when `--keep-last` protects more data than the byte
limit. Preserve the JSON result as deletion evidence and verify retained runs.
See [the bundled event reference](../skills/heimdall/references/events.md) for
the complete schema and `jq` recipes.

## Performance baseline

Run the repeatable current and Linux 6.6 LTS disposable-VM baselines after
changes that can affect setup, relay, capture, TLS, event writing, or teardown:

```bash
nix develop -c just benchmark-vm
```

Each VM emits one `HEIMDALL_BENCHMARK_JSON=` line containing its
`heimdall.benchmark/v1` document. Each covers cold start, direct TCP, proxied
TCP/UDP, relay TLS, maximum process RSS, 1/10/50 concurrent cold starts, and
post-run event integrity. Its `throughput` records measure sustained direct and
proxied TCP, proxied UDP, full transport capture, and relay TLS plaintext
capture, with transferred bytes, elapsed nanoseconds, bytes per second, and
the active capture/decrypt boundary. Event integrity requires zero incomplete
runs, sequence gaps, out-of-order records, active or failed flows, and error
events. Treat every result as specific to the reported architecture, kernel,
CPU count, and VM resources; it is a repeatable environment baseline, not a
universal throughput claim.

For relay TLS certificate failures, inspect `tls.error` before changing trust:

- `tls_upstream_certificate_invalid` means Heimdall rejected the remote peer
  during `upstream_handshake`; do not weaken upstream verification.
- `tls_upstream_client_auth_required` means the verified upstream requires a
  client certificate that relay mode cannot forward. Use runtime mode or turn
  decryption off; do not configure client key material in Heimdall.
- `tls_downstream_certificate_rejected` means the remote peer was verified,
  but the wrapped client rejected Heimdall's CA during
  `downstream_handshake`. Trust only the configured public `ca.pem` for that
  explicit command workflow.
- `tls_downstream_closed_without_close_notify` means the wrapped client closed
  without a reason visible at the TLS boundary. Curl can do this after a trust
  failure, but agents must preserve its stderr and exit status before drawing
  that conclusion.

## Capture and TLS

Run directories, payload blobs, and relay CA material are private to the user
who invokes `heimdall run`. Generate relay trust material as that user:

```bash
install -d -m 0700 "$HOME/.local/state/heimdall/tls"
ca_cert="$HOME/.local/state/heimdall/tls/ca.pem"
heimdall tls init-ca --dir "$HOME/.local/state/heimdall/tls" --json
```

Before trusting anything, compare `ca_cert_sha256` from `tls init-ca` with
`agent.config.decrypt.ca_cert_sha256`. Trust only the reported `ca_cert` in the
explicitly wrapped client, preferably without changing the machine trust store:

```bash
heimdall run -- curl --cacert "$ca_cert" https://example.com
heimdall run -- git -c http.sslCAInfo="$ca_cert" ls-remote https://example.com/repo.git
NODE_EXTRA_CA_CERTS="$ca_cert" heimdall run -- node client.js
REQUESTS_CA_BUNDLE="$ca_cert" heimdall run -- python client.py
```

Client-specific variables and flags are not universal; preserve native roots
when the client replaces rather than extends its trust bundle. Keep
`ca-key.pem` mode 0600 and never give it to the wrapped client. Relay mode is
library-independent but is incompatible with certificate pinning and
client-certificate mTLS.

Runtime mode changes no trust and currently observes only the reported OpenSSL
APIs. Ensure a representative `libssl` image is already mapped before starting
the run; setup fails before exec if no image can be attached:

```bash
heimdall agent | jq '{execution, capabilities: .capabilities.decrypt}'
heimdall run -- curl https://example.com
```

## Common failures

- `unknown policy`: choose one from `heimdall agent` or declare it under
  `proxy.policies`.
- ambiguous config discovery: keep exactly one `config.toml`, `config.yaml`,
  `config.yml`, or `config.json`, or pass global `--config PATH`.
- setup worker denied: verify the binary path and exact sudoers command; do not
  grant broader sudo access.
- cgroup permission error: ensure the systemd user manager is running; Heimdall
  re-enters a delegated `systemd-run --user --scope` and preserves `--config`.
- fake-DNS lookup failure: verify unprivileged user namespaces are enabled so
  the child can receive its private resolver mount.
- relay CA key permission error: generate the key as the invoking user and keep
  its containing directory 0700 and key 0600.
- another transparent proxy catches relay traffic: exempt the exact loopback
  endpoint reported for the run from that proxy's interception.
- runtime TLS has no attachable image: start a representative process using
  the same OpenSSL image before `heimdall run`, or use relay mode.
