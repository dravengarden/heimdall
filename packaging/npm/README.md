# heimdall-egress

This npm package distributes the official `heimdall` CLI. Heimdall runs one
Linux command through an explicit TCP/UDP proxy and can record transparent TLS
evidence without installing or starting a daemon.

## Install

```bash
npm install --global heimdall-egress
heimdall --version
```

For an ephemeral CLI or compatibility check:

```bash
npx heimdall-egress --version
npx heimdall-egress help
```

The package contains the official static x86_64 and aarch64 Linux musl
binaries. It has no install lifecycle script and does not download or execute
code from another host during installation. macOS is not supported yet.

## Transparent proxy setup

`heimdall run` attaches a command-scoped cgroup eBPF data path through the
narrow `__setup-worker` entry point. A global npm installation has a stable
native path; print it with:

```bash
heimdall-egress --print-native-path
```

Authorize exactly that regular native binary followed by `__setup-worker`, as
described in the [installation guide](https://dravengarden.github.io/heimdall/docs/install.html).
Do not authorize the Node launcher, an npm cache glob, arbitrary Heimdall
arguments, or a shell. Because an `npx` cache path is not a stable authorization
boundary, use a global or native installation for `heimdall run`.

Configuration, JSONL events, captures, and TLS CA material remain owned by the
invoking user. See the [documentation](https://dravengarden.github.io/heimdall/)
and [source](https://github.com/dravengarden/heimdall).
