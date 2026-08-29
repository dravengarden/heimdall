# Runbook

## Build

Refresh the pinned eBPF ELF first because it is embedded in the single
userspace binary and the crates.io source package.

```bash
nix develop -c just sync-ebpf
nix develop -c just verify
```

`just verify` includes this explicit Darwin compile boundary:

```bash
nix develop -c just check-macos
```

It type-checks the target-selected CLI and portable unit-test targets for
pinned `aarch64-apple-darwin`. It proves that shared config/init,
`RunEvidence`, `relay_transport`, the JSONL store and offline log CLI, and the
reduced explicit-agent contract do not compile Linux-only aya/cgroup code. It
does not link or execute a native binary and is not the macOS acceptance gate.

On a native Apple-silicon Mac, run:

```bash
just test-macos-native
```

This pinned release-mode gate runs the Darwin unit tests, builds the source
CLI, then routes `curl` through the `macos-explicit` loopback SOCKS5 CONNECT
listener and a fixture upstream. It verifies domain preservation, shared
policy routing, cooperative `policy.decision`/`flow.open`/`flow.close` JSONL,
offline integrity, listener teardown, exit-code passthrough, and fail-closed
backend selection. It does not accept strict process scope, UDP, fake DNS,
capture, TLS inspection, the future Network Extension, or official macOS
packaging.

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

Run the pinned non-NixOS compatibility gate on an x86_64 Linux KVM host:

```bash
just test-vm-ubuntu
just test-vm-debian
```

This boots the content-hashed Ubuntu 24.04 cloud image with QEMU user-mode
networking, installs the same native archive used for release, and grants an
ordinary user only the exact setup-worker sudo rule. It proves cgroup v2 and
systemd-user integration, copied-binary authorization denial, direct TCP/UDP,
fake DNS through SOCKS5 while AppArmor and its default user-namespace
restriction remain enabled, descendant lifetime, all four forwarded owner
signals, concurrent isolation, parent-death cleanup and recovery, runtime and
relay TLS, JSONL verification, exit propagation, and return to the pre-run
process, listener, command-cgroup, and BPF-pin state. The harness also rejects
any change to host links, routes, or rules. It is focused distribution
coverage, not a substitute for the broader NixOS protocol/stress matrix or
native aarch64 execution.

The same guest asserts that `heimdall agent --policy fake` selects
`port53_intercept`, reports the still-enabled AppArmor restriction, and needs
no private resolver mount.

The content-hashed Debian 13 guest runs the same archive, authorization,
lifecycle, TLS, log-integrity, cleanup, and host-isolation checks. Its stock
`files myhostname resolve [!UNAVAIL=return] dns` NSS line must select
`private_mount`, preserve the host resolver files, and complete fake DNS
without a session D-Bus service. The strict Python 3.13/OpenSSL client also
validates the generated relay CA and leaf extensions.

On an aarch64 Linux execution host, run the architecture-equivalent current
and LTS guests with:

```bash
nix develop .#acceptance -c just test-vm-native-aarch64
```

The recipe rejects a non-Linux or non-aarch64 host, and each guest asserts
`uname -m` before the data-path suite starts. This is the native-system gate;
the qemu-user CLI check in `test-package` is not a substitute. Until this gate
has a successful ARM Linux result, keep native aarch64 real-eBPF acceptance in
release notes as a known limitation.

Build both generic static archives, reject incorrect architecture, dynamic
linkage, private/build paths, and debug sections, verify embedded BTF metadata,
exercise the aarch64 CLI under emulation, and run native x86_64 install,
upgrade, and rollback acceptance:

```bash
nix develop -c just test-package
```

Local release verification is authoritative. From a clean `main` checkout that
exactly matches `origin/main`, publish only with:

```bash
just release-github
```

This runs source verification, then the current and Linux 6.6 LTS NixOS
real-eBPF guests and the pinned Ubuntu 24.04 and Debian 13 compatibility guests
sequentially, then the native archive, npm, PyPI, and Cargo package checks. Only
after every gate passes does it create the version tag and GitHub Release with
curated notes, archives, and checksums. The versioned changelog must include
highlights and known limitations; see
[releasing.md](releasing.md) for the complete release contract. GitHub Pages or
Actions status is not release evidence.

`just release-github` also uploads the locally built npm 12 tarball, two
platform-specific PyPI wheels, the Cargo CLI source package, and their
checksums. Publishing that Release automatically starts the project-owned
`publish-npm.yml`, `publish-pypi.yml`, and `publish-cargo.yml`; their native
registry CLIs publish through OIDC. The Cargo workflow first reproduces the
`.crate` file byte for byte from the immutable tag. Routine publication
has no Lasso invocation, local registry login, write token, 2FA link, or second
dispatch. See
[releasing.md](releasing.md) for the one-time trusted-publisher setup and
failure contracts.

The disposable NixOS VM proves fake/system DNS, SOCKS5 and direct TCP/UDP,
IPv4/IPv6, HTTP/3, static
and dynamic clients, descendants, exit/signal status, two concurrent isolated
runs, event rotation, relay TLS, fail-closed upstream errors, and return to the
pre-run BPF-link baseline. It also kills a live foreground owner and proves the
unprivileged helper removes the workload cgroup and BPF links.

The Ubuntu guest proves the release artifact and narrow authorization work on
a non-NixOS system without installing a service. It independently exercises
one fake-DNS SOCKS5 TCP route under Ubuntu's default AppArmor restriction,
direct TCP/UDP, descendants, signals, concurrent runs, owner-death recovery,
and runtime and relay TLS. It intentionally does not duplicate the NixOS
suite's SOCKS5 UDP, QUIC, broad runtime-client, capture/rotation, retention,
and stress coverage.

The Debian guest proves the same release and lifecycle boundary through the
private resolver-mount fallback selected for its nss-resolve status-action
chain. It also proves that the systemd user manager is sufficient without a
session D-Bus daemon and that strict OpenSSL clients accept Heimdall's generated
CA and leaves.

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
helper to discover and pre-attach OpenSSL images from active mappings,
standard library directories, and `/etc/ld.so.conf`. A loader-known image may
map after exec; if no supported image can be attached, setup fails before the
wrapped command starts.

Treat every `actions.*` command as an argv array; never concatenate or
shell-evaluate it. Consumers may rely on existing v8 field semantics and must
ignore additive unknown fields. Renaming or changing an existing semantic
requires a new contract version.

The in-development Darwin target preserves that rule while remaining not
ready: `platform.os = "macos"`, both entries in additive `backends` have
`available = false`, `execution = null`, and `actions.execute_prefix = null`.
Shared config and offline `logs` actions are exposed. These commands can print
schemas and inspect, verify, recover, or prune a compatible existing JSONL
store; they do not imply that a macOS backend can create traffic evidence.
`heimdall run` deterministically exits 1 without executing the supplied
command. A successful `aarch64-apple-darwin` type-check is not native backend
acceptance.

```bash
heimdall logs schema --event v1
heimdall logs list --json
heimdall logs verify --run <RUN_ID> --json
```

`actions.config_schema` and `actions.config_example_toml` are read-only and do
not require a valid or discoverable config file.
`capabilities.logs.flow_summary_contract`, `actions.logs_schema_flow`, and
`actions.logs_flow` expose the bounded per-flow explanation contract and its
parameterized argv without changing the v8 semantics.

Before execution, inspect:

- `config.valid`, normalized capture/decrypt values, capture allowlists,
  redaction-value readiness, relay `ca_material_ready`/`ca_material_error`, and
  stable diagnostics;
- `execution.backend`, `daemon_required`, and `privilege_setup`;
- `decision` for the selected policy and terminal TCP/UDP actions;
- `decision.resolver` for the selected DNS strategy, NSS/nscd reason,
  private-mount status, userns settings, readiness, and stable error code;
- every `actions.resolver_inspect[]` entry as an independent argv array, never
  as shell text;
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
heimdall logs schema --summary v1
heimdall logs schema --flow v1
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
heimdall logs flow --run RUN_ID --flow FLOW_ID --json
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
capture-truncation totals, and DNS/policy/TLS/HTTP counters. Export its strict
offline contract with `logs schema --summary v1`. The summary is an operational
aggregation, not a substitute for `logs verify`, which validates schemas,
segment digests, sequences, and referenced blobs.

`logs flow` emits one `heimdall.logs.flow/v1` document for an exact run/flow
pair. It explains route and transport outcome, capture by fixed direction and
boundary, whether plaintext bytes were actually observed, TLS/HTTP counters,
and error evidence without copying payload, headers, or SNI. Its `actions`
remain argv arrays. Error-code counts are evidence-record counts: one failure
may appear in both `tls.error.data.code` and the correlated
`flow.close.data.error_code`. Export the offline contract with
`logs schema --flow v1`, and run the returned `actions.verify` before making an
integrity claim.

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

Run the repeatable current and Linux 6.6 LTS NixOS baselines and the pinned
Ubuntu 24.04 and Debian 13 baselines after changes that can affect setup, relay,
capture, TLS, event writing, or teardown:

```bash
nix develop -c just benchmark-vm
just benchmark-vm-ubuntu
just benchmark-vm-debian
```

Each VM emits one `HEIMDALL_BENCHMARK_JSON=` line containing its
`heimdall.benchmark/v1` document. Each covers cold start, direct TCP, proxied
TCP/UDP, relay TLS, maximum process RSS, 1/10/50 concurrent cold starts, and
post-run event integrity. Its `throughput` records measure sustained direct and
proxied TCP, proxied UDP, full transport capture, and relay TLS plaintext
capture, with transferred bytes, elapsed nanoseconds, bytes per second, and
the active capture/decrypt boundary. Event integrity requires zero incomplete
runs, sequence gaps, out-of-order records, active or failed flows, and error
events. The NixOS guests use GNU time resource accounting. Ubuntu and Debian
use fake DNS with SOCKS5 routing, procfs RSS sampling, and 8 GiB guests so the
50-run batch does not turn into a memory pressure test; the Ubuntu gate does
not weaken its default AppArmor user-namespace restriction. Treat every result
as specific to the reported distribution,
architecture, kernel, CPU count, memory, and RSS source. These commands are
explicit performance checks, not part of `release-check`, and their output is
an environment baseline rather than a universal throughput claim.

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
accepted only when `agent.config.decrypt.ca_material_ready` is true. If
`ca_material_error.code` is `relay_ca_material_invalid`, generate replacement
material in a new private directory, update command-scoped client trust, then
change both config paths. Do not overwrite the trusted CA until every affected
client is ready for the replacement. Relay mode is
library-independent but is incompatible with certificate pinning and
client-certificate mTLS.

Runtime mode changes no trust and currently observes only the reported OpenSSL
APIs. Setup pre-attaches active and system-loader `libssl` images before
dropping privilege. A loader-known image may map after exec, but a private
image outside those paths remains opaque. Setup fails before exec if no image
can be attached:

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
  A separate session D-Bus service is not required.
- fake-DNS lookup failure: a host with a plain `hosts: files dns` NSS path uses
  direct cgroup port-53 interception and needs no user namespace. Read
  `decision.resolver` first and execute each `actions.resolver_inspect[]` argv
  independently. `fake_dns_user_namespace_disabled` fails before run state or
  the workload exists; choose `dns.mode = "system"` or use a compatible host.
  For an `apparmor_policy_check`, grant only the exact installed Heimdall path
  `userns,` through a scoped profile when authorized. Do not relax Ubuntu's
  system-wide restriction. See the
  [Ubuntu 24.04 security notes](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).
- relay CA key permission error: generate the key as the invoking user and keep
  its containing directory 0700 and key 0600.
- `relay_ca_material_invalid`: generate replacement CA material in a new
  private directory, update command-scoped client trust, then update both relay
  config paths. Do not weaken certificate validation or silently overwrite a
  CA that clients still trust.
- another transparent proxy catches relay traffic: exempt the exact loopback
  endpoint reported for the run from that proxy's interception.
- runtime TLS has no attachable image: install the supported OpenSSL shared
  library in a standard loader directory or declare its directory through the
  host's loader configuration; otherwise use relay mode. Heimdall will not keep
  a privileged runtime monitor merely to discover a private image.
