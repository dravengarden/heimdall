# Security policy

heimdall sits on the data path: it loads eBPF programs into the
kernel, intercepts `connect()` syscalls, and reads plaintext TLS
buffers via uprobes. Bugs in any of those layers can leak traffic,
crash the host, or escalate privileges. We take security reports
seriously.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security problems.

Instead, file a [private vulnerability
report](https://github.com/dravengarden/heimdall/security/advisories/new)
through GitHub's Security Advisories feature. Include:

- The version (`heimdall --version`) or commit hash
- Kernel version (`uname -r`) and distribution
- A minimal reproduction (eBPF program loaded, config snippet, the
  exact command / pod that triggers the issue)
- Impact assessment (does it leak traffic? crash the host? escalate
  caps from a wrapped CLI to root?)
- Whether you'd like credit in the advisory and under what name

We aim to acknowledge reports within **3 working days** and ship a
fix or coordinated disclosure within **30 days** for high-severity
issues.

## Scope

In scope:

- The daemon (`heimdall serve`) and its eBPF programs
- The HTTP / WebSocket API (`/api/*`)
- The `heimdall run` cgroup + mount-namespace machinery
- The fake-IP DNS server
- Configuration parsing (heimdall-config)

Out of scope:

- Issues in upstream dependencies that don't manifest through
  heimdall's surface area — please report those upstream.
- DoS via misconfiguration (pointing `runtime.cgroup` at
  `/sys/fs/cgroup` and observing CPU is expected behaviour).
- The Web UI's same-origin trust model — heimdall doesn't try to be
  a multi-tenant control plane.
- Kernel bugs triggered by eBPF programs heimdall doesn't load.

## Threat model snapshot

Heimdall assumes:

- The host is single-tenant. Anyone with a shell on the box has equal
  trust to the daemon (root or in the right groups).
- `runtime.apiListen` is bound to localhost or LAN. Don't expose it
  to the internet — there's no auth on the API.
- The SOCKS5 upstream is trusted. heimdall forwards plaintext TLS
  destinations (ATYP=0x03) to it; an evil upstream can MITM via
  cert injection on the upstream-of-the-upstream side, but heimdall
  itself doesn't inject CAs.
- eBPF programs are loaded by the daemon (uid 0 with `CAP_BPF`).
  They run with kernel privileges and bypass DAC.

Out of scope today:
- Confidentiality of `state_dir` (sqlite + future blobs). Plaintext
  captured by the tap is stored unencrypted; treat the host as
  trusted-or-not accordingly.
- Multi-user isolation on the same host. Anyone with `/run/heimdall`
  access can register cgroups (currently no auth on the register API).

## Hardening recommendations for operators

- Bind `apiListen` to `127.0.0.1:9999` unless you need LAN access.
- Run with the minimum capability set: `CAP_BPF`, `CAP_NET_ADMIN`,
  `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`. No others.
  The reference systemd unit in
  [`services/heimdall/`](https://github.com/your-org/your-nixos-config/tree/main/services/heimdall)
  is correct.
- Set `runtime.tap.persist = false` if you don't need to retain
  plaintext on disk.
- Audit `connections.<name>.auth.passwordFile` permissions
  (0400 root:root) — a 0644 leak compromises every upstream the
  daemon talks to.
