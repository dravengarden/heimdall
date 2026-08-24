# Install and upgrade

Heimdall ships one public executable: `heimdall`. Linux release archives are
reproducible x86_64 and aarch64 musl builds with the eBPF object embedded in
that executable. They do not install or start a daemon.

## Requirements

- x86_64 or aarch64 Linux 5.10 or newer;
- cgroup v2 and a running systemd user manager;
- `sudo` for the narrow per-run setup worker;
- a reachable SOCKS5 server for proxied policies.

The release binary has no dynamic libc dependency. Kernel, cgroup, privilege,
and TLS-library compatibility requirements still apply. The x86_64 package is
covered by native install and real-eBPF VM acceptance. The aarch64 package is
checked for static linkage and architecture and executes CLI acceptance under
emulation; native aarch64 real-eBPF acceptance remains active compatibility
work.

## Install through npm

The public `heimdall-egress` package embeds both official Linux musl binaries.
It has no install lifecycle script and performs no install-time download:

```bash
npm install --global heimdall-egress
heimdall --version
```

`npx` is suitable for help, version, configuration, and compatibility checks:

```bash
npx heimdall-egress --version
npx heimdall-egress help
```

Transparent `heimdall run` setup must authorize a stable regular native binary,
not the Node launcher or an npm cache glob. With a global npm installation,
print that path with:

```bash
heimdall-egress --print-native-path
```

Use the printed path in the narrow sudoers rule below. An `npx` cache path is
not stable enough for this authorization boundary, so use a global npm or
native archive installation for `heimdall run`.

## Install through PyPI

The public `heimdall-egress` project provides separate x86_64 and aarch64
Linux wheels that work on glibc and musl systems. Each wheel embeds one static
native binary, requires Python 3.9 or newer, and performs no install-time build
or download:

```bash
uv tool install heimdall-egress
# or: pipx install heimdall-egress
# or inside an isolated environment: python -m pip install heimdall-egress
heimdall --version
```

For ephemeral help and compatibility checks:

```bash
uvx --from heimdall-egress heimdall --version
pipx run --spec heimdall-egress heimdall help
```

For a persistent installation, print the regular bundled binary path with
`heimdall-egress --print-native-path` and use it in the narrow sudoers rule
below. Do not authorize a Python console-script wrapper or ephemeral tool-cache
path. Use a persistent `uv tool`, `pipx`, or virtual-environment installation
for real `heimdall run` sessions.

## Install a tagged release

Download the archive and checksum from the matching GitHub release. With the
GitHub CLI:

```bash
version=0.1.2
architecture=$(uname -m)
case "$architecture" in x86_64|aarch64) ;; *) exit 1 ;; esac
gh release download "v$version" --repo dravengarden/heimdall \
  --pattern "heimdall-egress-$version-$architecture-linux-musl.tar.gz*"
archive="heimdall-egress-$version-$architecture-linux-musl.tar.gz"
sha256sum -c "$archive.sha256"
tar -xzf "$archive"
cd "heimdall-egress-$version-$architecture-linux-musl"
sudo ./heimdall-install install
heimdall --version
```

The installer validates the bundled executable, writes versioned state below
`/usr/local/lib/heimdall`, and atomically replaces the regular file
`/usr/local/bin/heimdall`. That stable non-symlink path is the only path that
should appear in sudoers.

Initialize invoking-user-owned configuration after installation:

```bash
heimdall init
heimdall config validate --json
```

Do not run `heimdall init` with `sudo`. Configuration, event logs, captures,
and TLS CA material belong to the invoking user.

## Authorize setup

Create `/etc/sudoers.d/heimdall` with `visudo`, replacing `USERNAME`. Native
archive installations use `/usr/local/bin/heimdall`; npm and PyPI installations
must use the exact native path printed by
`heimdall-egress --print-native-path`:

```sudoers
USERNAME ALL=(root) NOPASSWD: /usr/local/bin/heimdall __setup-worker
```

Then validate its permissions and syntax:

```bash
sudo chmod 0440 /etc/sudoers.d/heimdall
sudo visudo -cf /etc/sudoers.d/heimdall
```

This authorization permits one hidden setup mode, not arbitrary Heimdall
arguments and not a shell. Do not add file capabilities or setuid to the
binary.

## Upgrade and rollback

Extract the new release, verify its checksum, and run its installer again:

```bash
sudo ./heimdall-install install
sudo /usr/local/lib/heimdall/heimdall-install verify
```

An upgrade retains one previous executable. Roll back atomically with:

```bash
sudo /usr/local/lib/heimdall/heimdall-install rollback
heimdall --version
```

Rollback covers the complete embedded executable, including its eBPF object
and machine-readable contracts. It does not rewrite user configuration or
logs. Review pre-1.0 schema changes before moving between releases.

For an unprivileged packaging test, use an absolute private prefix:

```bash
./heimdall-install install --prefix "$PWD/test-root"
./test-root/lib/heimdall/heimdall-install verify --prefix "$PWD/test-root"
```

## Build from source

Use the pinned Nix toolchains and build eBPF before userspace:

```bash
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'
nix develop -c cargo build --workspace --locked --release
sudo install -Dm755 target/release/heimdall /usr/local/bin/heimdall
```

The source-built binary has the same daemonless lifecycle but is not the
generic static release artifact. See [runbook.md](runbook.md) for acceptance
and diagnostics.
