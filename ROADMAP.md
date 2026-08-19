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
- `heimdall agent` as a read-only `heimdall.agent/v7` preflight with argv-safe
  actions, selected execution ownership, and capability evidence.
- Daemonless foreground execution for all decrypt modes:
  each run owns isolated relay/DNS ports, maps, links, cgroup, event state, and
  a setup helper that drops privilege before the workload starts.
- Phase 1 per-run `heimdall.event/v1` lifecycle and TCP/UDP flow metadata,
  offline schemas, writer-owned rotation, integrity verification, and the
  agent-first `heimdall logs` CLI.
- Bounded private, invoking-user-owned capture under the
  `heimdall.capture/v1` contract.
- Relay TLS termination and startup-discovered OpenSSL runtime TLS probes in
  the foreground path.
- No background service, machine-wide control plane, or persistent kernel
  state in the shipped CLI.
- A real-eBPF NixOS acceptance VM covering dual-stack TCP/UDP, QUIC, common
  CLI/runtime clients, lifecycle behavior, and both TLS paths.

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
runtime and relay TLS, normal cleanup, and parent-death cgroup teardown.

- Evaluate run-scoped dynamic attachment for `libssl` images loaded only after
  child exec without introducing a persistent broker.
- Measure setup-worker authorization UX across supported distributions and
  extend abnormal-exit coverage beyond the current SIGKILL acceptance.
- Keep any persistent acceleration mode explicit and opt-in; never start it
  implicitly.

Acceptance target: all three decrypt modes run without enabling a Heimdall
service, while preserving independent concurrent runs, exit/signal semantics,
normal cleanup, and fail-closed owner-death cleanup. See
[docs/design/daemonless-runtime.md](docs/design/daemonless-runtime.md).

### 2. Agent-first event store

- Extend the available per-run `heimdall.event/v1` JSONL segments and
  `heimdall.run/v1` manifest beyond lifecycle and TCP/UDP metadata.
- Store large or binary payloads as content-addressed blobs instead of inline
  base64, with metadata-only capture as the default.
- Extend the available offline schemas and `logs` commands with payload-aware
  filters and age-based rotation.
- Keep the available rotation writer-owned and loss-aware; do not support
  external `copytruncate` against active logs.
- Publish exhaustive schema and Linux-tool recipes in the bundled Heimdall
  skill.

Acceptance target: an agent can discover paths and schemas without guessing,
follow a run across rotation, select flows with `jq`, verify blobs and segment
integrity, and distinguish opaque transport from actual TLS plaintext. See
[docs/design/agent-event-log.md](docs/design/agent-event-log.md).

### 3. Proxy compatibility and diagnostics

- Expand the runtime matrix across kernel versions, libc behaviors, socket API
  variants, and process-tree edge cases.
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
- Harden relay TLS compatibility around ALPN, SNI, certificate errors,
  client-authentication, pinning, and long-lived connections.
- Improve CA initialization, trust-store guidance, and diagnostics for clients
  that do not accept the relay certificate.

Acceptance target: runtime and relay modes report their actual coverage and
never claim plaintext visibility when the selected boundary was not attached or
trusted.

### 5. Capture analysis workflow

- Make bounded capture easier to inspect without changing its explicit payload
  boundary or strict private ownership.
- Add deterministic metadata and filtering primitives for agent-assisted flow
  triage.
- Document retention, redaction, and failure behavior for production-like
  capture directories.

Acceptance target: an operator or agent can identify the capture boundary,
select a flow, and explain why bytes are opaque or plaintext without guessing
from file names or process names.

## Planned

### Packaging and distribution

- Publish reproducible Linux artifacts with an installation path that keeps
  transient setup privilege and user-owned session/log state separate.
- Document upgrade and rollback boundaries for the embedded eBPF object,
  daemonless runtime, and machine-readable contracts.

### Performance and observability

- Establish repeatable throughput, latency, memory, and event-loss baselines
  for TCP, UDP, capture, and TLS modes.
- Measure daemonless cold start, per-run authorization, teardown, and 1/10/50
  concurrent runs before considering an opt-in acceleration service.
- Expose enough low-cardinality health data for operators to distinguish policy,
  relay, DNS, eBPF, and TLS-boundary failures.

### Configuration ergonomics

- Improve schema discoverability and generated examples while keeping one
  format-independent model and strict cross-format semantics.
- Publish each future pre-1.0 schema change as one complete current contract;
  do not add aliases or hidden compatibility parsing.

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
