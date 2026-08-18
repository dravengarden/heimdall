# Security policy

heimdall sits on the data path: it loads eBPF programs into the kernel,
intercepts `connect()` syscalls for wrapped commands, and relays selected
connections through SOCKS5. TLS records are forwarded unchanged unless the
user explicitly selects relay TLS inspection. Bugs in these layers can leak
traffic, expose captured bytes, crash the host, or escalate privileges. We
take security reports seriously.

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

- The short-lived `heimdall __setup-worker`, FD-transfer protocol, and eBPF
  programs
- The foreground relay, DNS, TLS, capture, and event-log path
- The explicit compatibility daemon and its loopback control API
- The `heimdall run` cgroup + mount-namespace machinery
- The fake-IP DNS server
- Configuration parsing (heimdall-config)

Out of scope:

- Issues in upstream dependencies that don't manifest through
  heimdall's surface area — please report those upstream.
- DoS via an operator-selected invalid config or unavailable upstream.
- Kernel bugs triggered by eBPF programs heimdall doesn't load.

## Threat model snapshot

Heimdall assumes:

- The operator authorizes each allowed user for the exact installed
  `heimdall __setup-worker` sudo command. Broader sudo, setuid, or file
  capabilities on the complete binary are outside the supported model.
- The setup worker authenticates its Unix-socket peer and confines a non-root
  caller to its own systemd user slice. Multi-user isolation beyond this
  boundary has not yet received dedicated acceptance coverage.
- The compatibility `daemon.api_listen` remains loopback-only. Do not expose
  it to the network; that legacy control protocol has no authentication.
- The SOCKS5 upstream is trusted. heimdall forwards destination hostnames
  (SOCKS5 ATYP=0x03) to it; an evil upstream can MITM via
  cert injection on the upstream-of-the-upstream side. Relay TLS explicitly
  uses a user-generated CA only when selected. RFC 1929 username/password authentication is
  plaintext on the connection to the SOCKS5 server, so use it only over a
  trusted local or otherwise protected transport.
- eBPF programs are loaded by the short-lived root setup worker. They run with
  kernel privileges; the unprivileged foreground owner retains only map/link
  FDs and cannot attach a different cgroup through that protocol.

The compatibility daemon remains a single-tenant legacy boundary: any local
process able to reach its control listener can attempt registration. Do not
enable it unless runtime TLS or explicit persistent-state maintenance requires
it.

## Hardening recommendations for operators

- Install the binary at an immutable administrator-owned path and authorize
  only that exact path plus `__setup-worker` in sudoers. Validate the fragment
  with `visudo -cf`.
- Keep the foreground user's run, capture, password, and relay-CA-key files
  private. Directories should be 0700 and private keys 0600.
- If the compatibility daemon is enabled, keep `api_listen` loopback-only and
  retain only `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and
  `CAP_DAC_OVERRIDE` in its systemd capability set.
- Audit every `proxy.outbounds.<name>.auth.password_file`; a readable leak
  compromises that upstream credential.
