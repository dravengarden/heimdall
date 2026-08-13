# heimdall

Proxychains-style, command-scoped SOCKS5 proxying for AI agents and CLI tools,
powered by cgroup eBPF.

Run one command through a named egress policy without modifying it:

```bash
heimdall run -- curl https://example.com
heimdall run --policy corp -- ssh internal.example.com
```

For an AI agent, start with one side-effect-free preflight:

```bash
heimdall agent
```

It emits one versioned JSON document with config validity, stable error codes,
daemon reachability, the resolved policy, declared policies/outbounds, and
the exact next commands as argv arrays. Exit `0` means ready, `1` means not
ready, and clap reserves `2` for invalid CLI usage.

Heimdall is deliberately a Linux CLI tool, not an orchestrator or a
host-wide policy engine. Processes that were not started by `heimdall run`
are left alone.

Unlike `proxychains4`, heimdall does not use `LD_PRELOAD`. A small privileged
daemon attaches cgroup eBPF hooks; the unprivileged CLI places only the
wrapped command in a transient cgroup. This also covers static binaries and
lets DNS names be resolved by the upstream proxy.

> **Status: alpha.** Linux 5.10+, cgroup v2, and systemd user scopes are
> currently required.

## Configuration

Keep exactly one configuration file under `/etc/heimdall`: `config.toml`,
`config.yaml`/`config.yml`, `config.json`, or `config.ncl`. The extension selects
the parser; every syntax uses the same strict schema. Multiple discovered files,
unknown or duplicate fields, wrong types, bad references, unsupported protocol
capabilities, contradictory rules, malformed addresses, and invalid CIDRs are
rejected with stable paths and repair hints.

```toml
version = 1

[proxy]
default_policy = "default"

[proxy.outbounds.default]
type = "socks5"
server = "127.0.0.1"
server_port = 1080
network = ["tcp"]

[proxy.policies.default.dns]
mode = "fake"

[proxy.policies.default.final]
tcp = { type = "route", outbound = "default" }
udp = { type = "reject", method = "refused" }

[capture]
mode = "off"

[decrypt]
mode = "off"
```

Optional authentication keeps the password out of the config:

```toml
[proxy.outbounds.default.auth]
username = "alice"
password_file = "/etc/heimdall/secrets/default-password"
```

Policies contain ordered TCP rules with `route`, `direct`, or `reject` actions
and mandatory TCP/UDP final actions. Fake DNS preserves hostnames for domain
rules; system DNS exposes resolved IPs. Non-DNS UDP is rejected until a real UDP
relay exists. See [docs/config.md](docs/config.md) for the complete schema.

## Getting started

```bash
# eBPF must be built before userspace because it is embedded in the binary.
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c cargo build --workspace --locked --release

sudo ./target/release/heimdall init
# Or: init --format yaml|json|nickel
sudo ./target/release/heimdall daemon

./target/release/heimdall run -- curl https://example.com
```

In production, install [`deploy/heimdall.service`](deploy/heimdall.service)
and run the CLI as an ordinary user.

## Command surface

```text
heimdall run [--policy NAME] -- COMMAND [ARGS...]
heimdall agent [--policy NAME]
heimdall daemon
heimdall status [--json]
heimdall config validate|explain|show|path
heimdall init [--dir PATH] [--format toml|yaml|json|nickel] [--force]
```

The daemon owns only the relay, fake-IP DNS, local control endpoint, eBPF
maps, and stale CLI-cgroup cleanup. See [docs/architecture.md](docs/architecture.md)
for the boundary and [docs/runbook.md](docs/runbook.md) for operations.

`heimdall agent` never writes configuration, starts the daemon, registers a
cgroup, or runs a command. Consumers should execute the returned
`actions.execute_prefix` array followed by their own command arguments, without
joining it into a shell string.

## Requirements

- Linux 5.10 or newer
- cgroup v2
- a running systemd user manager
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and `CAP_DAC_OVERRIDE` for
  the daemon
- a SOCKS5 server
- `nickel` when using `.ncl` outside the Nix package (the Nix package includes it)

Licensed under Apache-2.0.
