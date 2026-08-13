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

## Agent contract

`heimdall agent [--policy NAME]` is the automation entry point.
It is read-only and always prints exactly one JSON value before exiting:

```json
{
  "contract": "heimdall.agent/v2",
  "version": "0.1.0",
  "ready": true,
  "config": { "path": "...", "format": "toml", "valid": true, "error": null },
  "daemon": { "reachable": true, "control": "127.0.0.1:9999" },
  "capabilities": {
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
      "udp_ipv6": ["go-netgo", "java", "nodejs", "python", "rust"]
    },
    "cli_acceptance": { "tcp_fake_dns": ["git"] },
    "lifecycle": {
      "descendant_cgroup_lifetime": true,
      "exit_code_passthrough": true,
      "signal_exit_code": "128+signal",
      "upstream_unreachable_fail_closed": true,
      "daemon_unreachable_prevents_exec": true,
      "daemon_restart_continuity": false,
      "daemon_restart_policy_recovery": true,
      "daemon_restart_fake_dns_recovery": true,
      "daemon_restart_existing_connections": false
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
    "execute_prefix": ["heimdall", "--config", "...", "run", "--policy", "default", "--"]
  },
  "exit_codes": { "ready": 0, "not_ready": 1, "usage": 2 }
}
```

Treat argv arrays as arrays; never concatenate or shell-evaluate them. When
config cannot be loaded, `config.error.code` is a stable category and
`diagnostics` contains stable code/path/message/hint records. The contract may
add fields within v2; consumers
must ignore unknown fields.

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

`capabilities.cli_acceptance` records end-to-end evidence for concrete CLI
protocols; Git is tested with `git ls-remote` over fake-DNS TCP. Agents must
also inspect `capabilities.lifecycle`. A wrapped command keeps its policy until
all descendants leave the cgroup, preserves normal exit and signal status,
fails rather than bypassing an unreachable upstream, and is not executed when
the daemon cannot register it. Active command policies and fake-DNS mappings
recover once a restarted daemon is ready, as reported by the two
`daemon_restart_*_recovery` fields. `daemon_restart_continuity` remains false:
stopping the daemon removes its process-owned eBPF links, leaves a temporary
interception gap, and does not preserve existing connections. Do not run a
workflow that requires uninterrupted enforcement or connection survival across
a daemon restart.

## Common failures

- `unknown policy`: declare it below `proxy.policies` or choose a name reported
  by `heimdall agent`.
- ambiguous config discovery: keep exactly one `config.toml`, `config.yaml`,
  `config.yml`, `config.json`, or `config.ncl` in `/etc/heimdall`, or pass an
  explicit `--config` path.
- Nickel export failure: install `nickel` when using a manually copied binary;
  the Nix package includes it automatically.
- daemon registration connection refused: start `heimdall.service` and confirm
  `daemon.api_listen` matches the client config.
- DNS lookup failure in fake mode: verify unprivileged user namespaces are
  enabled and the child received its private resolver mount.
- cgroup permission error: ensure the user's systemd manager is running; the
  CLI uses `systemd-run --user --scope` to enter a delegated subtree.
- another transparent proxy catches relay traffic: exempt the exact local
  relay endpoint from that proxy's interception rules.

Stopping heimdall removes the eBPF links, so normal host networking remains
available. During an explicit service restart, systemd preserves the root-only
runtime journal; after readiness, still-running wrapped commands regain their
policy and fake-DNS mappings. They are not enforced during the link replacement
window, and connections established before the restart are not preserved.
Unregistered processes bypass heimdall while it is running.
