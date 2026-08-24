# heimdall-egress

The official npm distribution of `heimdall`: a daemonless, command-scoped
TCP/UDP proxy with optional transparent TLS evidence for Linux CLI tools and AI
agents.

## Install

Every command below installs the same npm package, which contains static Linux
x86_64 and aarch64 musl binaries. It has no install lifecycle script and does
not download executable code during installation.

```bash
# npm
npm install --global heimdall-egress

# pnpm
pnpm add --global heimdall-egress

# Bun
bun add --global heimdall-egress

# Yarn Classic 1.x
yarn global add heimdall-egress

# Deno 2.8+; -A lets the Node-compatible launcher start the bundled binary
deno install --global -A --name heimdall npm:heimdall-egress
```

Modern Yarn intentionally has no global install command; use `yarn dlx` below.
Deno installs a persistent command backed by its npm cache, but that cache is
not a durable privileged-authorization boundary. Use npm, pnpm, Bun, Yarn
Classic, or a native GitHub Release for real proxy sessions. macOS is not
supported yet.

Verify the installed command:

```bash
heimdall --version
```

## Run without installing

Use these for `--version`, `help`, and compatibility checks:

```bash
npx --yes --package=heimdall-egress -- heimdall --version
pnpm dlx --package heimdall-egress heimdall --version
yarn dlx --package heimdall-egress heimdall --version
bunx --package heimdall-egress heimdall --version
deno x -A --package heimdall-egress heimdall --version
```

These runners use package-manager caches. Their paths are not stable enough for
Heimdall's narrow privileged setup authorization, so do not use them for
`heimdall run`. Use a persistent package-manager or native installation for
real proxy sessions.

## Quick start

Create the strict starter configuration and inspect readiness without changing
network state:

```bash
heimdall init
heimdall agent
```

`heimdall run` needs one narrowly authorized setup entry point. For a
persistent Node package-manager installation, print the exact bundled binary
path:

```bash
heimdall-egress --print-native-path
```

Authorize only that regular file followed by `__setup-worker`, as shown in the
[installation guide](https://dravengarden.github.io/heimdall/docs/install.html).
Do not authorize the JavaScript launcher, arbitrary Heimdall arguments, a
package cache glob, or a shell.

Then run one command through the selected policy:

```bash
heimdall run -- curl https://example.com
heimdall run --policy corp -- ssh internal.example.com
```

Inspect the resulting machine-readable evidence with ordinary Linux tools or
the built-in log commands:

```bash
heimdall logs list --json
heimdall logs summary --run RUN_ID --json
heimdall logs query --run RUN_ID --kind flow.close --jsonl
```

## Architecture

```text
heimdall run -- COMMAND
        |
        +-- transient command cgroup + embedded eBPF links
        +-- per-run relay + fake DNS + JSONL writer
        `-- command tree
                `-- TCP/UDP -> policy -> SOCKS5, direct, or reject
```

The foreground CLI owns the complete session: cgroup, relay, DNS, eBPF maps and
links, logs, child exit status, and teardown. The privileged setup worker only
attaches eBPF, transfers owned file descriptors, drops privilege, and guards
the command tree. No persistent Heimdall daemon or Web UI is installed or
started in any mode.

## Modes

Proxying, payload capture, and TLS plaintext observation are independent:

- **Proxy only** — `decrypt.mode = "off"` routes TCP/UDP while TLS remains
  opaque. Policies choose named SOCKS5 outbounds, direct egress, or rejection.
- **Bounded capture** — `capture.mode = "on"` writes private,
  content-addressed evidence and JSONL references under the invoking user.
  Boundary and direction allowlists plus environment-value redaction run
  before retention.
- **Runtime TLS** — `decrypt.mode = "runtime"` observes supported OpenSSL APIs
  already loaded when the command starts. It does not change certificate trust
  and makes no claim for unsupported TLS libraries.
- **Relay TLS** — `decrypt.mode = "relay"` terminates and re-issues TLS inside
  the per-run relay using explicit user-owned CA material. Certificate pinning
  and client-certificate mTLS are outside this boundary.

Selecting a mode is not proof that plaintext was observed. Use `heimdall agent`
and the emitted event boundary as evidence.

## Documentation

- [Documentation](https://dravengarden.github.io/heimdall/)
- [Installation and setup](https://dravengarden.github.io/heimdall/docs/install.html)
- [Architecture](https://dravengarden.github.io/heimdall/docs/architecture.html)
- [Source](https://github.com/dravengarden/heimdall)
- [Issues](https://github.com/dravengarden/heimdall/issues)
- [Releases](https://github.com/dravengarden/heimdall/releases)
