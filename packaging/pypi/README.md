# heimdall-egress

The official PyPI distribution of `heimdall`: a daemonless, command-scoped
TCP/UDP proxy with optional transparent TLS evidence for Linux CLI tools and AI
agents.

## Install

Install the persistent CLI with the Python tool manager you already use:

```bash
# uv (recommended)
uv tool install heimdall-egress

# pipx
pipx install heimdall-egress

# pip inside an isolated environment
python -m pip install heimdall-egress
```

The package contains one static native binary selected by the wheel resolver.
Official wheels support x86_64 and aarch64 Linux on glibc and musl systems,
require Python 3.9 or newer, and do not run install hooks or download executable
code during installation. macOS is not supported yet.

Verify the installed command:

```bash
heimdall --version
```

## Run without installing

Use an ephemeral environment for help, version, configuration, and
compatibility checks:

```bash
uvx --from heimdall-egress heimdall --version
pipx run --spec heimdall-egress heimdall --version
```

Ephemeral tool caches are not a stable eBPF authorization boundary. Use `uv
tool install`, `pipx install`, a persistent virtual environment, or a native
GitHub Release for `ebpf` sessions. They may run `interpose` or `explicit`
because neither reduced backend needs privileged setup.

## Quick start

Create the strict starter configuration and inspect readiness without changing
network state:

```bash
heimdall init
heimdall agent
```

The generated starter explicitly selects the strict Linux `ebpf` backend. It needs one narrowly authorized
setup entry point; for a persistent Python installation, print the exact
bundled native path:

```bash
heimdall-egress --print-native-path
```

Authorize only that regular file followed by `__setup-worker`, as shown in the
[installation guide](https://dravengarden.github.io/heimdall/docs/install.html).
Do not authorize the Python launcher, a virtual-environment glob, arbitrary
Heimdall arguments, or a shell.

For a no-privilege reduced session, explicitly select `interpose` for
compatible dynamic calls or `explicit` for clients that honor a SOCKS proxy
environment. Reject every UDP path and keep capture/decrypt off; `explicit`
also requires system DNS. Run `heimdall agent` and verify the reported scope.

Then run one command through the selected policy:

```bash
heimdall run -- curl https://example.com
heimdall run --policy corp -- ssh internal.example.com
```

Inspect machine-readable evidence with ordinary Linux tools or the built-in
log commands:

```bash
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
heimdall logs query --run RUN_ID --kind flow.close --jsonl
```

## Architecture

```text
heimdall run -- COMMAND
        |
        +-- backend
        |   +-- ebpf: cgroup links; TCP/UDP, DNS, optional capture/TLS
        |   +-- interpose: LD_PRELOAD; compatible TCP/libc DNS calls
        |   `-- explicit: child ALL_PROXY; cooperative TCP clients
        `-- per-run relay + policy + JSONL -> SOCKS5, direct, or reject
```

The foreground CLI owns the relay, policy, logs, child exit status, and
teardown. In `ebpf`, it additionally owns the cgroup, DNS, maps, and links; the
setup worker attaches eBPF, transfers owned file descriptors, drops privilege,
and guards the command tree. `interpose` uses no cgroup or setup worker and can
be bypassed by static code, direct syscalls, alternate APIs, loader removal,
inherited sockets, and unsupported descendants. `explicit` can be bypassed by
clients that ignore or replace the proxy environment. No persistent Heimdall daemon or Web UI is installed or started in any mode.

## Modes

Proxying, payload capture, and TLS plaintext observation are independent:

- **Execution backend** — choose `ebpf`, `interpose`, or `explicit`; the field
  is required and there is no automatic selection or fallback.
- **Proxy only** — `decrypt.mode = "off"` routes TCP/UDP while TLS remains
  opaque. Policies choose named SOCKS5 outbounds, direct egress, or rejection.
- **Bounded capture** — `capture.mode = "on"` writes private,
  content-addressed evidence and JSONL references under the invoking user.
- **Runtime TLS** — `decrypt.mode = "runtime"` observes supported OpenSSL APIs
  already loaded when the command starts without changing certificate trust.
- **Relay TLS** — `decrypt.mode = "relay"` terminates and re-issues TLS inside
  the per-run relay using explicit user-owned CA material.

Selecting a mode is not proof that plaintext was observed. Use `heimdall agent`
and emitted events as evidence. Certificate pinning, client-certificate mTLS,
and unsupported TLS libraries remain outside the observation boundary.

## Documentation

- [Documentation](https://dravengarden.github.io/heimdall/)
- [Installation and setup](https://dravengarden.github.io/heimdall/docs/install.html)
- [Architecture](https://dravengarden.github.io/heimdall/docs/architecture.html)
- [Source](https://github.com/dravengarden/heimdall)
- [Issues](https://github.com/dravengarden/heimdall/issues)
- [Releases](https://github.com/dravengarden/heimdall/releases)
