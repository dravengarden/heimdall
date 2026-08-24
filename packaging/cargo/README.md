# heimdall-egress

This crate installs the official `heimdall` CLI. Heimdall runs one Linux
command and its descendants through an explicit TCP/UDP egress policy, with
optional bounded capture and transparent TLS inspection. It does not install
or start a daemon.

## Install

```bash
cargo install heimdall-egress --locked
heimdall --version
```

The crate compiles the Rust userspace CLI and embeds the release's verified
eBPF object. Installation performs no network download outside Cargo's normal
crate and dependency resolution, and has no install script. Rust 1.95 or newer
is required. Native macOS is not supported yet.

## Quick start

```bash
heimdall init
heimdall agent
heimdall run -- curl https://example.com
```

Real proxy sessions require Linux 5.10+, cgroup v2, a running systemd user
manager, and narrow `sudo` authorization for the exact installed binary
followed by `__setup-worker`. Find the regular Cargo-installed path first:

```bash
command -v heimdall
```

Authorize exactly that path as described in the
[installation guide](https://dravengarden.github.io/heimdall/install.html).
Do not authorize arbitrary Heimdall arguments, a Cargo cache glob, or a shell.

## Architecture

`heimdall run` creates one foreground-owned session. A narrow setup worker
attaches cgroup eBPF hooks, transfers the owned resources to the CLI, and drops
privilege before the wrapped command starts. The same foreground process owns
the relay, DNS, policy, JSONL evidence, maps, and links until every descendant
exits. There is no persistent Heimdall daemon.

## Modes

- Proxying routes TCP and UDP through ordered direct or SOCKS5 policies.
- Capture records bounded opaque transport evidence and optional payload blobs.
- Runtime TLS inspection observes supported OpenSSL calls without changing
  trust.
- Relay TLS inspection terminates command-scoped TLS with invoking-user-owned
  CA material.
- The optional Web UI is a read-only log consumer and is not required.

Use `heimdall help -v` for the complete CLI surface and `heimdall agent` for a
single-document JSON readiness report designed for AI agents.

## Links

- [Documentation](https://dravengarden.github.io/heimdall/)
- [Source](https://github.com/dravengarden/heimdall)
- [Issues](https://github.com/dravengarden/heimdall/issues)
