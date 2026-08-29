# heimdall-egress

This crate installs the official `heimdall` CLI. Linux provides strict
command-tree TCP/UDP egress policy with optional bounded capture and
transparent TLS inspection. Apple silicon provides the deliberately reduced
`macos-explicit` cooperative TCP backend. Neither platform installs or starts
a daemon.

## Install

```bash
cargo install heimdall-egress --locked
heimdall --version
```

The crate compiles the Rust userspace CLI and embeds the release's verified
eBPF object. Installation performs no network download outside Cargo's normal
crate and dependency resolution, and has no install script. Rust 1.95 or newer
is required. Supported source-build targets are x86_64/aarch64 Linux and
aarch64 macOS 11 or newer.

## Quick start

```bash
heimdall init
heimdall agent
heimdall run -- curl https://example.com
```

Strict transparent proxy sessions require Linux 5.10+, cgroup v2, a running
systemd user manager, and narrow `sudo` authorization for the exact installed
binary followed by `__setup-worker`. Find the regular Cargo-installed path
first:

```bash
command -v heimdall
```

Authorize exactly that path as described in the
[installation guide](https://dravengarden.github.io/heimdall/install.html).
Do not authorize arbitrary Heimdall arguments, a Cargo cache glob, or a shell.

On Apple silicon, first select a compatible config with system DNS, rejected
UDP, capture off, and decrypt off. Continue only when `heimdall agent` reports
`ready: true`, then append the workload to its exact
`actions.execute_prefix`. The equivalent CLI shape is:

```bash
heimdall --config /path/to/config.toml run \
  --backend macos-explicit --policy default -- \
  curl https://example.com
```

This sets only child `ALL_PROXY`/`all_proxy`; the client may bypass them. It
needs no `sudo`, system proxy change, daemon, or Network Extension and makes no
strict-scope, UDP, fake-DNS, capture, TLS-inspection, QUIC, or fail-closed
claim.

## Architecture

`heimdall run` creates one foreground-owned session. A narrow setup worker
attaches cgroup eBPF hooks, transfers the owned resources to the CLI, and drops
privilege before the wrapped command starts. The same foreground process owns
the relay, DNS, policy, JSONL evidence, maps, and links until every descendant
exits. That is the Linux path. On Apple silicon, one foreground loopback SOCKS5
CONNECT listener evaluates shared TCP route/direct/reject policy and records
cooperative metadata until the immediate child exits.
There is no persistent Heimdall daemon.

## Modes

- Linux proxying routes TCP and UDP through ordered direct or SOCKS5 policies.
- Linux capture records bounded opaque transport evidence and optional payload blobs.
- Linux runtime TLS inspection observes supported OpenSSL calls without changing
  trust.
- Linux relay TLS inspection terminates command-scoped TLS with invoking-user-owned
  CA material.
- macOS explicit mode provides cooperative TCP route/direct/reject and metadata
  only.
- The optional Web UI is a read-only log consumer and is not required.

Use `heimdall help -v` for the complete CLI surface and `heimdall agent` for a
single-document JSON readiness report designed for AI agents.

## Links

- [Documentation](https://dravengarden.github.io/heimdall/)
- [Source](https://github.com/dravengarden/heimdall)
- [Issues](https://github.com/dravengarden/heimdall/issues)
