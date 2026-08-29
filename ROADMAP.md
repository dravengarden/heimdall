# Heimdall roadmap

This document is the public planning surface for Heimdall. It describes
capability boundaries and acceptance targets, not delivery dates. A feature is
only moved to **available** when its contract, failure behavior, and relevant
acceptance path are documented and tested.

## Status definitions

| Status | Meaning |
| --- | --- |
| Available | Usable in the current alpha with a documented contract and an acceptance path |
| In development | Actively being hardened or expanded; expect compatibility work and contract review |
| Planned | Direction accepted, but implementation has not started or is not yet committed |
| Deferred | Intentionally out of the current product boundary |

## Available today

- Command-scoped TCP and UDP proxying through cgroup eBPF, without
  `LD_PRELOAD`.
- Named SOCKS5 outbounds, direct egress, ordered TCP/UDP rules, fake DNS, and
  explicit reject actions.
- Strict TOML, YAML, and JSON configuration with shared validation, stable
  diagnostic codes, JSON paths, and repair hints.
- An offline JSON Schema generated from that model, plus complete read-only
  starter examples in every supported syntax.
- `heimdall agent` as a read-only `heimdall.agent/v8` preflight with argv-safe
  actions, selected execution ownership, and capability evidence.
- Daemonless foreground execution for all decrypt modes:
  each run owns isolated relay/DNS ports, maps, links, cgroup, event state, and
  a setup helper that drops privilege before the workload starts.
- Per-run `heimdall.event/v1` lifecycle, TCP/UDP metadata, and bounded
  content-addressed payload blobs, with offline schemas, byte/age rotation,
  integrity verification, payload-aware filters, and `heimdall logs`.
- Low-cardinality `heimdall.logs.summary/v1` run health derived from the
  append-only evidence, including sequence loss, active flows, failures,
  capture truncation, and protocol-boundary counters, with a strict offline
  schema for agent validation.
- Payload boundary/direction allowlists and environment-backed exact-value
  redaction before hashing or blob publication.
- Per-flow/direction bounded payload block coalescing with explicit size,
  latency, index, and flush-reason evidence.
- Conservative HTTP/1 request/response header records derived only from
  explicit TLS plaintext, with parser provenance, source-event sequence links,
  fixed masking for common credential headers, and no retained body copy.
- Dry-run-first recovery of orphaned runs that rejects active owners and
  finalized-segment mutation while preserving discarded tail evidence.
- Foreground SIGHUP/SIGINT/SIGQUIT/SIGTERM forwarding with finalized exit and
  signal evidence, plus deterministic non-interactive setup authorization.
- Correlated fake-DNS query/answer evidence, ordered policy-decision evidence,
  and explicit OpenSSL runtime-observation metadata.
- Relay TLS termination and startup-discovered OpenSSL runtime TLS probes in
  the foreground path.
- Stable relay TLS failure evidence distinguishes invalid upstream
  certificates, explicit downstream certificate alerts, and downstream closes
  that reveal no certificate-specific reason.
- No background service, machine-wide control plane, or persistent kernel
  state in the shipped CLI.
- A real-eBPF NixOS acceptance matrix on the current and Linux 6.6 LTS kernels,
  covering dual-stack TCP/UDP, QUIC, common CLI/runtime clients, lifecycle
  behavior, and both TLS paths.
- A pinned Ubuntu 24.04 x86_64 KVM gate that installs the native release
  archive, grants only the setup-worker sudo rule, rejects copied-binary
  authorization, and proves fake DNS through SOCKS5 without relaxing AppArmor's
  user-namespace restriction, direct TCP/UDP, descendant lifetime, all four
  owner signals, concurrent isolation, parent-death cleanup and recovery,
  runtime and relay TLS evidence, JSONL integrity, daemonless cleanup, and
  host-network isolation.
- Machine-readable current/LTS NixOS and pinned Ubuntu 24.04 real-eBPF
  benchmarks covering daemonless latency, RSS, 1/10/50 concurrent starts,
  sustained TCP/UDP and capture throughput, and event integrity without
  requiring a metrics service.
- Reproducible static x86_64 and aarch64 Linux archives with checksums,
  authoritative local release gates, atomic installation, one-level executable
  rollback, and artifact-hygiene checks. The embedded eBPF object has
  deterministic source roots and no DWARF while retaining BTF/BTF.ext. The
  aarch64 package has structural and emulated CLI acceptance; native aarch64
  real-eBPF execution remains in the compatibility track.

The current available implementation is Linux-only. macOS support is planned
below and is not part of the available contract yet.

## In development

These are the active engineering tracks. They deliberately improve the core
proxy and its evidence before adding a larger control plane.

### 1. Daemonless lifecycle hardening

The foreground data plane is now the default for every decrypt mode. It binds
kernel-assigned per-run relay and DNS ports, creates fresh unpinned maps,
attaches FD-owned links through `heimdall.setup/v2`, and closes every resource
when the command tree exits. The real-eBPF VM proves concurrent isolated runs,
runtime and relay TLS, owner signal forwarding, normal cleanup, deterministic
authorization denial, and parent-death cgroup teardown. The pinned Ubuntu 24.04
gate independently proves those lifecycle boundaries, both TLS modes, release
installation, user-manager re-entry, exact authorization, direct TCP/UDP, logs,
and normal cleanup outside NixOS.

- Evaluate run-scoped dynamic attachment for `libssl` images loaded only after
  child exec without introducing a persistent broker.
- Extend the available NixOS and Ubuntu lifecycle matrix across additional
  distributions and process-tree edge cases.
- Keep any persistent acceleration mode explicit and opt-in; never start it
  implicitly.

Acceptance target: all three decrypt modes run without enabling a Heimdall
service, while preserving independent concurrent runs, exit/signal semantics,
normal cleanup, and fail-closed owner-death cleanup. See
[docs/design/daemonless-runtime.md](docs/design/daemonless-runtime.md).

### 2. Agent-first event store

- Extend the available per-run event store beyond HTTP/1 headers only when a
  protocol parser can remain bounded, provenance-linked, and conservative.
- Keep stable `event_store_full` diagnostics around bounded block coalescing
  and atomic blob publication.
- Keep the available rotation writer-owned and loss-aware; do not support
  external `copytruncate` against active logs.
- Keep exhaustive event, run, and summary schemas plus bounded Linux-tool
  recipes in the bundled Heimdall skill.

Acceptance target: an agent can discover paths and schemas without guessing,
follow a run across rotation, select flows with `jq`, verify blobs and segment
integrity, and distinguish opaque transport from actual TLS plaintext. See
[docs/design/agent-event-log.md](docs/design/agent-event-log.md).

### 3. Proxy compatibility and diagnostics

- Keep the available namespace-free fake-DNS path for `files dns` NSS hosts
  configurations covered on pinned Ubuntu 24.04. The cgroup hook redirects the
  host resolver's port-53 traffic directly while AppArmor's default
  user-namespace restriction remains enabled.
- Expand namespace-free compatibility across NSS stacks that currently need
  the private resolver-mount fallback, without silently accepting D-Bus,
  multicast, or nscd paths that bypass cgroup DNS interception.
- Expand the available current/LTS NixOS and pinned Ubuntu 24.04 coverage
  across more distributions, libc behaviors, socket API variants, and
  process-tree edge cases.
- Turn more rejected or unsupported network shapes into stable agent-readable
  diagnostics with a clear repair command or an explicit fail-closed reason.
- Keep extending dual-stack, UDP, and HTTP/3 acceptance without weakening
  source-port ownership or peer-identity guarantees.

Acceptance target: every supported path has a documented family/protocol
boundary, deterministic failure semantics, and a VM or focused regression
test.

### 4. TLS boundary hardening

- Expand runtime capture beyond the currently supported OpenSSL probe surface
  only when the library boundary can be made explicit and safe.
- Expand relay TLS compatibility beyond the available ALPN/SNI preservation,
  long-lived stream acceptance, and stable client-authentication/trust-boundary
  failure diagnostics. Pinning and client-certificate mTLS remain explicit
  unsupported relay boundaries rather than compatibility claims.
- Expand CA integration beyond the available certificate fingerprint matching
  and command-scoped curl, Git, Node.js, and Python trust guidance. Some clients
  close without an alert, so `tls_downstream_closed_without_close_notify` still
  requires the wrapped command's stderr and exit status.

Acceptance target: runtime and relay modes report their actual coverage and
never claim plaintext visibility when the selected boundary was not attached or
trusted.

### 5. Capture analysis workflow

- Extend the available boundary/direction/blob filters and HTTP/1 header
  evidence with bounded inspection that does not weaken strict private
  ownership.
- Expand the available pre-storage allowlist and exact-value redaction model
  only where the failure boundary remains deterministic and agent-readable.
- Expand production-like private run-store retention beyond the available
  explicit preview/apply, active-run protection, protected-limit reporting,
  deletion evidence, and retained-run verification acceptance.

Acceptance target: an operator or agent can identify the capture boundary,
select a flow, and explain why bytes are opaque or plaintext without guessing
from file names or process names.

### 6. Performance and observability

The current and Linux 6.6 LTS NixOS VMs and pinned Ubuntu 24.04 guest emit a
machine-readable `heimdall.benchmark/v1` baseline for daemonless cold start,
direct TCP, proxied TCP/UDP, relay TLS, maximum process RSS, event integrity,
and 1/10/50 concurrent runs. They also record sustained direct and proxied TCP,
proxied UDP, transport capture, and relay TLS plaintext-capture throughput.
Results are explicitly environment-specific rather than product-wide
performance claims.

- Repeat the functional and performance contracts across distributions beyond
  the current/6.6 LTS NixOS and Ubuntu 24.04 matrix.
- Keep operational health low-cardinality and derived from the same per-run
  evidence used by agents; do not add a required metrics daemon.

Acceptance target: a repeatable environment records latency, memory,
concurrency, sustained transport throughput, and event loss for TCP, UDP,
capture, and TLS without changing the daemonless product boundary.

### 7. Release artifact hygiene and native ARM acceptance

The artifact-hygiene half is available: source paths are remapped before BTF
generation, LLVM removes the redundant DWARF before embedding, BTF/BTF.ext and
their relocations are required, and package gates reject private/build paths,
Nix store paths, debug sections, dynamic interpreters, and dynamic
dependencies on both release architectures.

- Keep the hygiene gate aligned across native archives, npm, PyPI, and the
  Cargo source package whenever packaging changes.
- Execute the available `aarch64-linux` current and Linux 6.6 LTS real-eBPF VM
  outputs on an ARM Linux host; structural and qemu-user CLI checks do not
  satisfy this target.
- Add that native result to the release transaction only after a repeatable ARM
  Linux executor exists.

Acceptance target: x86_64 and aarch64 Linux archives remain reproducible and
static, contain no private or build-path evidence, preserve required eBPF
metadata, and pass native current/LTS data-path acceptance on each supported
architecture.

## Planned

### macOS backend and fallback

- Add a macOS wrapper backend for `heimdall run` using native proxy settings or
  a bounded `proxychains-ng` fallback. Report its reduced capabilities
  explicitly: best-effort command scope, TCP-only fallback behavior, and no
  runtime TLS inspection.
- Add a signed macOS companion app/system extension backed by
  `NETransparentProxyProvider` for transparent TCP and UDP flow handling.
  Evaluate `NEAppProxyProvider` for per-app or managed deployments rather than
  treating it as a direct cgroup equivalent.
- Define policy handoff, lifecycle, concurrent sessions, DNS, fail-closed
  behavior, and relay self-protection between the CLI and the macOS provider.
- Preserve shared policy, relay, and TLS semantics across platforms without
  claiming Linux cgroup-equivalent command scope until process attribution and
  acceptance coverage are proven.

Acceptance target: macOS wrapper and transparent-provider paths have separate
capability contracts and acceptance coverage for TCP, UDP, QUIC, DNS, process
scope, relay recovery, and TLS boundaries.

## Deferred product boundaries

The following are intentionally not on the current roadmap:

- Kubernetes, cluster orchestration, or a host-wide policy controller.
- A replacement VPN, desktop traffic dashboard, or host-wide always-on system
  proxy.
- A workload policy language layered on top of the small proxy schema.
- A fourth first-class configuration syntax.
- Claims of universal TLS decryption across every language, TLS library, or
  certificate-pinning implementation.

A read-only, explicitly started viewer for completed or live event files is
planned after the event schema stabilizes. It has no data-plane, TLS, or policy
authority and is not required by any CLI feature.

These boundaries keep Heimdall focused on a reliable command wrapper and leave
application-specific inspection to explicit tools and trust decisions.

## How to influence the roadmap

Open an issue with a minimal command, configuration, kernel/runtime details,
and the output of `heimdall agent`. For larger changes, discuss the boundary
and acceptance criteria before opening a pull request. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
