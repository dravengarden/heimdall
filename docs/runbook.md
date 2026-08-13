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
fake/system DNS, SOCKS5 IPv4/IPv6/domain requests, direct/reject actions,
non-DNS UDP fail-closed behavior, unregistered bypass, cgroup cleanup, and 100
same-source-port dual-stack connection pairs.

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
available. Unregistered processes also bypass heimdall while it is running.
