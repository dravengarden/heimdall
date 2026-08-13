# heimdall

Proxychains-style, command-scoped SOCKS5 proxying for AI agents and CLI tools,
powered by cgroup eBPF.

Run one command through a named proxy without modifying that command:

```bash
heimdall run -- curl https://example.com
heimdall run -p corp -- ssh internal.example.com
```

For an AI agent, start with one side-effect-free preflight:

```bash
heimdall agent
```

It emits one versioned JSON document with config validity, stable error codes,
daemon reachability, the resolved proxy/DNS decision, declared proxy names, and
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
unknown fields, wrong types, bad references, malformed addresses, and invalid
CIDRs are rejected.

```toml
[proxies.default]
type = "socks5"
addr = "127.0.0.1:1080"

[proxies.corp]
type = "socks5"
addr = "127.0.0.1:1081"

[run]
proxy = "default"
dns = "fake"
```

Optional authentication keeps the password out of the config:

```toml
[proxies.corp.auth]
username = "alice"
passwordFile = "/etc/heimdall/secrets/corp-password"
```

`dns = "fake"` sends hostname resolution through heimdall so the SOCKS5
server resolves names. Use `dns = "system"` when the host resolver is
preferred.

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
heimdall run [-p NAME] [--dns fake|system] -- COMMAND [ARGS...]
heimdall agent [-p NAME] [--dns fake|system]
heimdall daemon
heimdall status [--json]
heimdall config validate|show|path
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
