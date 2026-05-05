# Changelog

All notable changes to heimdall are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html) once it tags a
`v0.1.0` release. Pre-tag changes live under `[Unreleased]`.

## [Unreleased]

### Added
- Project foundations: `LICENSE` (Apache 2.0), `CONTRIBUTING.md`,
  `SECURITY.md`, this `CHANGELOG.md`. README polished and pointed at
  the auto-generated `/etc/heimdall/README.md` for full schema docs.
- Orphan-cgroup GC. Daemon-side periodic task (30s tick) walks
  `/sys/fs/cgroup/user.slice` for empty `heimdall-cli-*` directories
  left behind by abnormal `heimdall run` exits and tears them down
  (cli_overrides + PolicyEngine.external + CGROUP_POLICY BPF map +
  rmdir). Requires `CAP_DAC_OVERRIDE` on the daemon.
- IPv6 across the stack: `cgroup_inet6_connect` (`connect6` BPF
  program), dual-stack `OrigDst` + `BypassEvent` (`addr: [u8; 16]` +
  `family` discriminator), `RELAY_ADDR6` BPF map, `runtime.relayIp6`
  + `runtime.fakeIp6Cidr` config, AAAA fake-IP synthesis (separate
  `V6Pool` in `dns.rs`), bypass-list for `::1` / `fe80::/10` /
  `ff00::/8` / IPv4-mapped, `skb_egress` IP-version detection plus
  bounded extension-header walker (Hop-by-Hop / Routing / Fragment /
  Destination Options / Mobility / HIP / Shim6, max 8 hops). Relay
  listens on `[::]:N` dual-stack; explicit IPs honoured as-is.
- `heimdall run` proxychains-style CLI proxy. Per-process cgroup +
  HTTP register API, `cli.run.{default,profiles}` config schema,
  `--connection / --profile / --observe / --dns / --tag /
  --print-decision / --keep-cgroup` flags. Non-root via
  `systemd-run --user --scope` re-entry plus an unprivileged
  user+mount namespace shim that bind-mounts a stripped-down
  nsswitch + resolv.conf and `/dev/null` over
  `/var/run/nscd/socket` so libc DNS reaches heimdall.
- DNS hijack policy bit (`POLICY_DNS_HIJACK`). When set on a
  cgroup, `connect4`, `connect6`, `udp4_sendmsg`, and `udp6_sendmsg`
  rewrite `:53` destinations to heimdall's fake-IP DNS port.
  Daemon writes its own DNS endpoint to `DNS_ADDR_V4` /
  `DNS_ADDR_V6` BPF maps at startup.
- `heimdall run` profile + flag chain now propagates `dns` field
  (was previously dropped silently).
- Skills package (agentskills.io format) under `skills/` —
  `heimdall-{flows,status,init,serve,config,run}` — installable via
  `bunx skills add` into Claude Code, Codex, Cursor, etc.
- v2raya iptables / ip6tables bypass for relay-bound traffic
  (`dst=relay_ip:12345 → RETURN/K8S_BYPASS` in TP_OUT/TP_PRE)
  shipped in the companion NixOS module
  (`services/k0s/k8s-v2raya-fix`).
- `flows` table now has an `idx_flows_atyp` index, and the list
  query / API / `heimdall flows list` accept an `atyp` filter
  (`ip` / `ip6` / `domain`) so users can drill into "show only the
  IPv6 traffic" or "show only DNS-hostname-resolved flows" without
  a regex on `dst_ip`.
- Flow table (CLI + Web UI) shows an `atyp` column; IPv6 dst
  literals are bracketed (`[2606:4700::1]:443`) in the dst cell,
  hover tooltip, and `flows show` detail view so they can be
  copy-pasted into `curl` without fixup.
- `heimdall status --json` emits a single-line JSON object with
  stable field names (`flows_in_store`, `relay_reachable`, …) so AI
  agents and shell scripts don't have to scrape the labeled-text
  view. The `heimdall-status` skill documents both modes.
- `heimdall help [subcommand…]` is now the canonical AI-discovery
  path: a recursive dump of every subcommand and every option in
  one read. `heimdall help flows` drills into one subtree;
  `heimdall help flows list` lands on a leaf. Clap's auto-generated
  `help` subcommand was removed in favour of this routing.
- `--help-all` global flag kept as an alias of `help`, so the same
  recursive output composes anywhere (`heimdall flows --help-all`,
  `heimdall run --help-all`, etc.). Plain `--help` / `-h` remains
  concise clap default + a footer line pointing at `heimdall help`
  for AI agents that scan only the first response.

### Changed
- `--config` no longer hard-codes a `[default: heimdall.ncl]` value
  in the help text. The flag is now `Option<PathBuf>`; when unset,
  the daemon and CLI subcommands auto-discover
  `/etc/heimdall/heimdall.{ncl,toml,json,yaml}` (existing behaviour
  unchanged, but the help text no longer lies for hosts that use a
  non-Nickel format).
- Daemon auto-discovers `/etc/heimdall/heimdall.{ncl,toml,json,yaml}`
  in that order; `--config` no longer needs to be spelled out in the
  systemd unit.
- `OrigDst` and `BypassEvent` shapes are dual-stack (`addr: [u8; 16]
  + family: u8`) — incompatible with pre-IPv6 daemons reading the
  same BPF map. Rebuild eBPF + userspace together.
- `PolicyEngine.reconcile` no longer wipes externally-registered
  CGROUP_POLICY entries; `external: HashSet<u64>` tracks CLI
  registrations and the delete-stale loop skips them.

### Fixed
- v2raya TPROXY would catch heimdall-relay-bound packets from host
  processes (everything outside the pod CIDR), short-circuiting the
  relay entirely. Two new K8S_BYPASS-chain rules whitelist the
  exact relay endpoint (10.244.0.41:12345 + ::1:12345).
- `heimdall run` registrations were silently wiped 0–5 s after
  registration by `PolicyEngine.reconcile` treating any
  non-pod-derived CGROUP_POLICY entry as stale.
- `cli.run.profiles[NAME].dns` was dropped on the floor by the run
  decision resolver — `dns: fake` in `cli.run.default` never reached
  the BPF map. Now propagates correctly.

## Pre-history

Initial development happened on a private repo. Major milestones,
chronologically:

- M1: rename from `ebpf-socks` to `heimdall`.
- Schema rewrite + named connections + RFC 1929 SOCKS5 auth.
- M3: pod identity (eBPF cgroup_id + kube-rs informer + cgroup walker).
- M4: routing engine (annotation > label > rules > default).
- Path C: fake-IP DNS + ATYP=0x03 hostname-mode SOCKS5 — internal /
  VPN-scoped hostnames resolve at the upstream proxy, not on the cluster.
- Phase B tap: libssl + Go (`crypto/tls.(*Conn).{Write,Read}` via
  `.gopclntab` + RET-offset uprobes) + rustls plaintext capture.
- Multi-format config loader (YAML / JSON / TOML / Nickel) +
  Nickel schema lib auto-generated by `heimdall init`.

Roadmap (not yet shipped):

- **M5 MITM** — TLS terminator + dynamic cert mint + HAR-format flow log.
- **M6 storage** — sqlite + blob with 3-day retention (partially landed).
- **M7 Web UI** — further polish.
- **M8 MCP / agent integration**.
- **JVM TLS tap** — JVMTI agent (native `.so`) loaded via
  `-agentpath:` / `JAVA_TOOL_OPTIONS`. Uses `RetransformClasses` to
  rewrite `sun.security.ssl.SSLEngineImpl.{wrap,unwrap}` so the
  decrypted buffer flows through a fixed-address native stub
  `heimdall_tls_observe(dir, buf, len)`. uprobe attaches to that stub
  the same way it does for libssl. Out-of-scope for the daemon
  itself (no Java code in this repo); will likely live as a sibling
  crate / artifact when it lands.
