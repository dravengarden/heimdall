# Security policy

heimdall sits on the data path: it loads eBPF programs into the kernel,
intercepts `connect()` syscalls for wrapped commands, and relays selected
connections through SOCKS5. It may inspect the TLS ClientHello to recover SNI
when fake DNS is not in use. Bugs in these layers can leak traffic, crash the
host, or escalate privileges. We take security reports seriously.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security problems.

Instead, file a [private vulnerability
report](https://github.com/dravengarden/heimdall/security/advisories/new)
through GitHub's Security Advisories feature. Include:

- The version (`heimdall --version`) or commit hash
- Kernel version (`uname -r`) and distribution
- A minimal reproduction (eBPF program loaded, config snippet, the
  exact command / unit that triggers the issue)
- Impact assessment (does it leak traffic? crash the host? escalate
  caps from a wrapped CLI to root?)
- Whether you'd like credit in the advisory and under what name

We aim to acknowledge reports within **3 working days** and ship a
fix or coordinated disclosure within **30 days** for high-severity
issues.

## Scope

In scope:

- The daemon (`heimdall daemon`) and its eBPF programs
- The loopback control API used by the CLI
- The `heimdall run` cgroup + mount-namespace machinery
- The fake-IP DNS server
- Configuration parsing (heimdall-config)

Out of scope:

- Issues in upstream dependencies that don't manifest through
  heimdall's surface area — please report those upstream.
- DoS via misconfiguration of daemon listener or cgroup paths.
- Kernel bugs triggered by eBPF programs heimdall doesn't load.

## Threat model snapshot

Heimdall assumes:

- The host is single-tenant. Anyone with a shell on the box has equal
  trust to the daemon (root or in the right groups).
- `daemon.apiListen` is bound to localhost. Don't expose it to the
  network; the control protocol has no authentication.
- The SOCKS5 upstream is trusted. heimdall forwards destination hostnames
  (SOCKS5 ATYP=0x03) to it; an evil upstream can MITM via
  cert injection on the upstream-of-the-upstream side, but heimdall
  itself doesn't inject CAs.
- eBPF programs are loaded by the daemon (uid 0 with `CAP_BPF`).
  They run with kernel privileges and bypass DAC.

Out of scope today:
- Multi-user isolation on the same host. Any local process able to reach the
  control listener can attempt to register a cgroup.

## Hardening recommendations for operators

- Keep `apiListen` on `127.0.0.1:9999`.
- Run with the minimum capability set: `CAP_BPF`, `CAP_NET_ADMIN`,
  `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`. No others.
  Drop anything else (e.g. `CAP_NET_RAW`, `CAP_SYS_RESOURCE`)
  via `CapabilityBoundingSet=` in the systemd unit.
- Audit `proxies.<name>.auth.passwordFile` permissions
  (0400 root:root) — a 0644 leak compromises every upstream the
  daemon talks to.
