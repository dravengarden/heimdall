# Runbook

## Build

Build eBPF first because the daemon embeds its ELF at compile time.

```bash
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c just verify
```

`just verify` covers deterministic build, lint, dependency, and unit gates.
Run the kernel data-plane acceptance separately when changing eBPF, cgroup,
DNS, relay correlation, or routing behavior:

```bash
nix develop -c just test-vm
```

The check boots a disposable NixOS guest and verifies real eBPF attachment,
fake/system DNS, SOCKS5 IPv4/IPv6/domain requests, connected UDP through SOCKS5
and direct egress, persistent association reuse, multi-response delivery,
sequential source-port reuse, transparent UDP peer identity, IPv4
connectionless multi-target traffic, concurrent IPv4 same-source-port sockets,
single-peer IPv6, fail-closed IPv6 multi-target/shared-port conflicts,
IPv4-mapped dual-stack UDP, `sendmmsg`/`recvmmsg`, token stress across 128
destinations, IPv4 and native IPv6 HTTP/3 with QUIC Retry and a 32 KiB response,
unregistered bypass, whole-descendant cgroup lifetime, command exit/signal
status, unavailable-daemon pre-exec failure, unreachable-upstream failure,
cgroup cleanup, Git's native protocol, and 100 same-source-port dual-stack TCP
connection pairs. It also compiles and executes static Go `netgo`, Java,
Node.js, and Rust clients through fake-DNS TCP plus connected IPv4 and IPv6
UDP. Existing C, curl, and Python fixtures cover syscall batching, HTTP, and
additional UDP shapes.

The VM also enables a deliberately small capture budget and validates TCP and
UDP `heimdall.capture/v1` files, bidirectional records, truncation, ordering,
and root-only permissions.

## Install

```bash
sudo install -Dm755 target/release/heimdall /usr/local/bin/heimdall
sudo /usr/local/bin/heimdall init
sudo install -Dm644 deploy/heimdall.service \
  /etc/systemd/system/heimdall.service
sudo systemctl daemon-reload
sudo systemctl enable --now heimdall
```

The daemon should bind only loopback listeners. Check it with:

```bash
heimdall status
systemctl status heimdall
journalctl -u heimdall -n 100
```

The relay must report `127.0.0.1:12345 + [::1]:12345`; fake DNS uses both
families on `daemon.dns_port`, and the control API uses the configured loopback
`daemon.api_listen`.

## Smoke test

```bash
heimdall agent | jq .
heimdall config validate
heimdall run -- curl -fsS https://example.com
heimdall run --policy corp -- curl -fsS https://internal.example.com
```

The wrapped command's exit status is heimdall's exit status. A daemon or
registration failure occurs before the command is executed.

## Event logs

Every successful `heimdall run` initialization creates a user-owned run below
`$XDG_STATE_HOME/heimdall/runs` (default `~/.local/state/heimdall/runs`). Phase
1 records lifecycle and TCP/UDP flow metadata; payload bytes remain in the
explicit root-only `heimdall.capture/v1` directory.

```bash
heimdall logs schema --event v1
heimdall logs list --json
heimdall logs query --run RUN_ID --kind flow.close --jsonl
heimdall logs tail --run RUN_ID --follow --jsonl
heimdall logs rotate --run RUN_ID --json
heimdall logs verify --run RUN_ID --json
```

Rotation never deletes data. Preview retention first; deletion requires
`--apply`:

```bash
heimdall logs prune --older-than 30d --keep-last 20 --json
heimdall logs prune --older-than 30d --keep-last 20 --apply --json
```

## Agent contract

`heimdall agent [--policy NAME]` is the automation entry point.
It is read-only and always prints exactly one JSON value before exiting:

```json
{
  "contract": "heimdall.agent/v4",
  "version": "0.1.0",
  "ready": true,
  "config": {
    "path": "...",
    "format": "toml",
    "valid": true,
    "capture": { "mode": "off", "directory": "/var/lib/heimdall/captures", "max_bytes_per_flow": 1048576 },
    "decrypt": { "mode": "off", "ca_cert": null, "ca_key": null, "ca_material_ready": true },
    "error": null
  },
  "daemon": {
    "reachable": true,
    "control": "127.0.0.1:9999",
    "health": {
      "contract": "heimdall.daemon.health/v2",
      "ready": true,
      "decrypt_mode": "off"
    },
    "error": null
  },
  "capabilities": {
    "capture": {
      "contract": "heimdall.capture/v1",
      "format": "jsonl",
      "tcp": true,
      "udp": true,
      "payload": "mode_dependent",
      "tls_plaintext": true
    },
    "logs": {
      "event_contract": "heimdall.event/v1",
      "run_contract": "heimdall.run/v1",
      "format": "jsonl",
      "lifecycle_events": true,
      "flow_events": "tcp+udp_metadata",
      "writer_owned_rotation": true,
      "content_addressed_blobs": false
    },
    "decrypt": {
      "modes": ["off", "runtime", "relay"],
      "runtime_libraries": ["openssl"],
      "runtime_apis": ["SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex"],
      "runtime_discovery": "loaded_images_at_daemon_start",
      "runtime_max_bytes_per_event": 256,
      "runtime_requires_attached_image": true,
      "runtime_requires_ca_trust": false,
      "runtime_supports_pinning_and_mtls": true,
      "relay_library_independent": true,
      "relay_requires_ca_trust": true,
      "relay_supports_pinning_and_mtls": false,
      "upstream_certificate_verification": true,
      "non_tls_passthrough": true
    },
    "udp": {
      "connected": true,
      "connectionless": false,
      "connectionless_ipv4": true,
      "connectionless_ipv6": false,
      "connectionless_ipv6_single_peer": true,
      "ipv4_mapped_ipv6_socket": true,
      "concurrent_shared_source_port": false,
      "concurrent_shared_source_port_ipv4": true,
      "concurrent_shared_source_port_ipv6": false,
      "association_reuse": true,
      "multi_response": true,
      "max_socks5_payload_bytes": 65245,
      "quic": "ipv4+ipv6-single-path",
      "quic_ipv4": true,
      "quic_ipv6": true,
      "quic_address_family_migration": false,
      "exchange": "bidirectional-session"
    },
    "runtime_acceptance": {
      "tcp_fake_dns": ["curl", "go-netgo", "java", "nodejs", "rust"],
      "udp_ipv4": ["c", "go-netgo", "java", "nodejs", "python", "rust"],
      "udp_ipv6": ["go-netgo", "java", "nodejs", "python", "rust"],
      "tls_runtime": ["curl-openssl"],
      "tls_relay": ["curl"]
    },
    "cli_acceptance": { "tcp_fake_dns": ["git"] },
    "lifecycle": {
      "descendant_cgroup_lifetime": true,
      "exit_code_passthrough": true,
      "signal_exit_code": "128+signal",
      "upstream_unreachable_fail_closed": true,
      "daemon_unreachable_prevents_exec": true,
      "daemon_restart_continuity": false,
      "daemon_restart_enforcement_continuity": true,
      "daemon_restart_policy_recovery": true,
      "daemon_restart_fake_dns_recovery": true,
      "daemon_restart_existing_connections": false,
      "pinned_state_schema": 1,
      "transactional_program_upgrade": true,
      "cleanup_requires_no_active_workloads": true
    }
  },
  "decision": {
    "policy": "default",
    "dns": "fake",
    "tcp_final": "route:default",
    "udp_final": "reject:refused",
    "error": null
  },
  "policies": ["default"],
  "outbounds": ["default"],
  "actions": {
    "validate": ["heimdall", "--config", "...", "config", "validate", "--json"],
    "status": ["heimdall", "--config", "...", "status", "--json"],
    "execute_prefix": ["heimdall", "--config", "...", "run", "--policy", "default", "--"],
    "tls_ca_init": null,
    "logs_schema_event": ["heimdall", "logs", "schema", "--event", "v1"],
    "logs_schema_run": ["heimdall", "logs", "schema", "--run", "v1"],
    "logs_list": ["heimdall", "logs", "list", "--json"]
  },
  "exit_codes": { "ready": 0, "not_ready": 1, "usage": 2 }
}
```

Treat argv arrays as arrays; never concatenate or shell-evaluate them. When
config cannot be loaded, `config.error.code` is a stable category and
`diagnostics` contains stable code/path/message/hint records. The contract may
add fields within v4; consumers
must ignore unknown fields.

Before enabling capture, agents must inspect `capabilities.capture`,
`capabilities.decrypt`, and the normalized capture/decrypt config. The agent
capability says plaintext is available, not that every file is plaintext.
Inspect each open record: `opaque_transport` is relay-observed transport;
`tls_plaintext` is decrypted content.

Runtime mode requires no trust change and currently covers only OpenSSL
images loaded when the daemon starts and the four APIs reported by
`runtime_apis`. The daemon refuses readiness when no image can be attached;
require a positive `daemon.health.runtime.attached_images` count. Restart
the daemon after introducing a different `libssl` image. Each event is bounded
by `runtime_max_bytes_per_event`.
Relay mode is language-independent but requires clients to trust the generated
CA and is incompatible with pinning and client-certificate mTLS. Generate its
material only with explicit trust authority:

```bash
sudo heimdall tls init-ca --dir /var/lib/heimdall/tls --json
```

The command prints a shell-safe JSON contract and matching config paths. Trust
only `ca_cert`; keep `ca_key` private to the daemon.

Capture files are sensitive and root-only. Inspect them without changing daemon
state:

```bash
sudo jq -s . /var/lib/heimdall/captures/<flow>.jsonl
```

There is no automatic retention. Operators must bound storage externally and
must not weaken directory or file permissions to make an agent workflow easier.

Agents must inspect the per-family fields in `capabilities.udp` before choosing
a UDP workload. The aggregate `connectionless` and
`concurrent_shared_source_port` fields are false because support is not
dual-stack. IPv4 supports both cases. IPv6 supports one peer per connectionless
socket and IPv4-mapped destinations, but not arbitrary multi-target use or
simultaneous sockets sharing one explicit port. Those conflicts are rejected
instead of being accepted with ambiguous response identity.
`quic: "ipv4+ipv6-single-path"` and the `quic_ipv4`/`quic_ipv6` booleans mean
HTTP/3 is acceptance-tested on either family. Agents must still reject workflows
that require `quic_address_family_migration` while that field is false.

`capabilities.runtime_acceptance` is evidence from the real-eBPF VM, not a
language allowlist. A runtime absent from one protocol array is unverified for
that protocol; it is not automatically rejected by the proxy. The current
matrix is:

| Path | Acceptance-tested clients |
|---|---|
| Fake-DNS TCP | curl, static Go `netgo`, Java, Node.js, Rust |
| IPv4 UDP | C, static Go `netgo`, Java, Node.js, Python, Rust |
| IPv6 UDP | static Go `netgo`, Java, Node.js, Python, Rust |
| Runtime TLS plaintext | curl with OpenSSL |
| Relay TLS plaintext | curl |

`capabilities.cli_acceptance` records end-to-end evidence for concrete CLI
protocols; Git is tested with `git ls-remote` over fake-DNS TCP. Agents must
also inspect `capabilities.lifecycle`. A wrapped command keeps its policy until
all descendants leave the cgroup, preserves normal exit and signal status,
fails rather than bypassing an unreachable upstream, and is not executed when
the daemon cannot register it. Active command policies and fake-DNS mappings
recover once a restarted daemon is ready, as reported by the two
`daemon_restart_*_recovery` fields. Pinned maps and atomic link updates
make `daemon_restart_enforcement_continuity` true: registered traffic remains
intercepted and fails closed while the relay is unavailable.
`daemon_restart_continuity` remains false because existing connections and
relay sessions do not survive. Do not run a workflow that requires connection
survival across a daemon restart.

The first upgrade from a release that did not pin cgroup links requires one
ordinary daemon restart to install them. Enforcement continuity applies to
later stops and restarts after that startup succeeds.

`pinned_state_schema` identifies the exact reusable map layout.
`transactional_program_upgrade` means link replacement uses kernel CAS and
rolls the whole generation back if any later replacement or readiness step
fails. An unknown schema is never auto-deleted or silently migrated.

## Common failures

- `unknown policy`: declare it below `proxy.policies` or choose a name reported
  by `heimdall agent`.
- ambiguous config discovery: keep exactly one `config.toml`, `config.yaml`,
  `config.yml`, or `config.json` in `/etc/heimdall`, or pass an
  explicit `--config` path.
- daemon registration connection refused: start `heimdall.service` and confirm
  `daemon.api_listen` matches the client config.
- DNS lookup failure in fake mode: verify unprivileged user namespaces are
  enabled and the child received its private resolver mount.
- cgroup permission error: ensure the user's systemd manager is running; the
  CLI uses `systemd-run --user --scope` to enter a delegated subtree.
- another transparent proxy catches relay traffic: exempt the exact local
  relay endpoint from that proxy's interception rules.

Stopping heimdall leaves its pinned eBPF maps and links active. Registered
cgroups fail closed until the relay returns; unregistered processes continue to
bypass heimdall. During an explicit service restart, systemd preserves the
root-only runtime journal; after readiness, still-running wrapped commands
regain their userspace policy decisions and fake-DNS mappings. Connections
established before the restart are not preserved.

## Remove persistent eBPF state

Stop the daemon, wait for every wrapped command to exit, then use the bounded
cleanup command instead of deleting bpffs paths manually:

```bash
sudo systemctl stop heimdall
sudo heimdall ebpf cleanup --json
```

The command emits one `heimdall.ebpf.cleanup/v1` document. Exit 0 means the
Heimdall-owned `/sys/fs/bpf/heimdall` tree was removed (or was already absent).
Exit 1 with `code = "daemon_active"` or `code = "active_workloads"` means it
made no change. Do not bypass these checks: removing links from a populated
command cgroup would turn a fail-closed outage into unproxied egress.
