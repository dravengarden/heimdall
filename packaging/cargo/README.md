# heimdall-egress

This crate installs the official `heimdall` CLI. Linux provides strict
command-tree TCP/UDP egress policy with optional bounded capture and
transparent TLS inspection. Linux provides both reduced backends; macOS
x86_64/aarch64 provides architecture-neutral `explicit`, while Apple silicon
also provides `interpose`. No backend installs or starts a daemon.

## Install

```bash
cargo install heimdall-egress --locked
heimdall --version
```

The crate compiles the Rust userspace CLI and embeds the release's verified
eBPF object. Installation performs no network download outside Cargo's normal
crate and dependency resolution, and has no package-manager lifecycle
installer. Rust 1.95 or newer and a native C compiler are required; use a
normal `cc` toolchain on Linux or Xcode Command Line Tools on macOS. Supported
source-build targets are x86_64/aarch64 Linux and x86_64/aarch64 macOS 11 or
newer.

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

To use the no-privilege dynamic-call backend on Linux or Apple silicon, set:

```toml
[execution]
backend = "interpose"
```

Reject UDP and keep capture/decrypt off. On Linux or macOS x86_64/aarch64,
`explicit` is a second reduced choice and additionally requires system DNS. Continue only when
`heimdall agent` reports `ready: true`, then append the workload to its exact
`actions.execute_prefix`. An equivalent explicit invocation is:

```bash
heimdall --config /path/to/config.toml run \
  --backend explicit --policy default -- \
  curl https://example.com
```

`interpose` injects the embedded private library into compatible dynamic calls;
`explicit` sets only child `ALL_PROXY`/`all_proxy`. Both can be bypassed outside
their documented frontend. They need no `sudo`, system proxy change, daemon,
or Network Extension and make no strict-scope, UDP, capture, TLS-inspection,
QUIC, or universal fail-closed claim.

## Architecture

`heimdall run` creates one foreground-owned session. A narrow setup worker
attaches cgroup eBPF hooks, transfers the owned resources to the CLI, and drops
privilege before the wrapped command starts. The same foreground process owns
the relay, DNS, policy, JSONL evidence, maps, and links until every descendant
  exits. That is the Linux eBPF path. Reduced backends use one foreground
loopback SOCKS5 CONNECT listener and the same TCP route/direct/reject policy;
`interpose` authenticates every injected client connection with a per-run
secret.
There is no persistent Heimdall daemon.

## Modes

- Linux proxying routes TCP and UDP through ordered direct or SOCKS5 policies.
- Linux capture records bounded opaque transport evidence and optional payload blobs.
- Linux runtime TLS inspection observes supported OpenSSL calls without changing
  trust.
- Linux relay TLS inspection terminates command-scoped TLS with invoking-user-owned
  CA material.
- Linux and Apple-silicon macOS interpose mode provides dynamic-call TCP
  route/direct/reject and metadata only.
- Linux and macOS x86_64/aarch64 explicit mode provides cooperative TCP
  route/direct/reject and metadata only.
- The optional Web UI is a read-only log consumer and is not required.

Use `heimdall help -v` for the complete CLI surface and `heimdall agent` for a
single-document JSON readiness report designed for AI agents.

## Links

- [Documentation](https://dravengarden.github.io/heimdall/)
- [Source](https://github.com/dravengarden/heimdall)
- [Issues](https://github.com/dravengarden/heimdall/issues)
