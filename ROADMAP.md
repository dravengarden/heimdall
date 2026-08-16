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
- `heimdall agent` as a read-only `heimdall.agent/v4` preflight with argv-safe
  actions and capability evidence.
- Bounded root-only opaque capture under the `heimdall.capture/v1` contract.
- OpenSSL runtime TLS probes and relay TLS termination under explicit
  `runtime` and `relay` modes.
- Recovery of active command policy and fake-DNS state across daemon restarts,
  with fail-closed behavior while the relay is unavailable.
- A real-eBPF NixOS acceptance VM covering dual-stack TCP/UDP, QUIC, common
  CLI/runtime clients, lifecycle behavior, and both TLS paths.

## In development

These are the active engineering tracks. They deliberately improve the core
proxy and its evidence before adding a larger control plane.

### 1. Proxy compatibility and diagnostics

- Expand the runtime matrix across kernel versions, libc behaviors, socket API
  variants, and process-tree edge cases.
- Turn more rejected or unsupported network shapes into stable agent-readable
  diagnostics with a clear repair command or an explicit fail-closed reason.
- Keep extending dual-stack, UDP, and HTTP/3 acceptance without weakening
  source-port ownership or peer-identity guarantees.

Acceptance target: every supported path has a documented family/protocol
boundary, deterministic failure semantics, and a VM or focused regression
test.

### 2. TLS boundary hardening

- Expand runtime capture beyond the currently supported OpenSSL probe surface
  only when the library boundary can be made explicit and safe.
- Harden relay TLS compatibility around ALPN, SNI, certificate errors,
  client-authentication, pinning, and long-lived connections.
- Improve CA initialization, trust-store guidance, and diagnostics for clients
  that do not accept the relay certificate.

Acceptance target: runtime and relay modes report their actual coverage and
never claim plaintext visibility when the selected boundary was not attached or
trusted.

### 3. Capture analysis workflow

- Make bounded capture easier to inspect without changing its explicit payload
  boundary or root-only ownership.
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
  daemon privileges and user CLI ownership separate.
- Document upgrade and rollback boundaries for the eBPF object, pinned maps,
  and machine-readable contracts.

### Performance and observability

- Establish repeatable throughput, latency, memory, and event-loss baselines
  for TCP, UDP, capture, and TLS modes.
- Expose enough low-cardinality health data for operators to distinguish policy,
  relay, DNS, eBPF, and TLS-boundary failures.

### Configuration ergonomics

- Improve schema discoverability and generated examples while keeping one
  format-independent model and strict cross-format semantics.
- Add safe config inspection and migration guidance for future pre-1.0 schema
  changes; do not silently accept removed fields or mode names.

## Deferred product boundaries

The following are intentionally not on the current roadmap:

- Kubernetes, cluster orchestration, or a host-wide policy controller.
- A replacement VPN, desktop traffic dashboard, or always-on system proxy.
- A workload policy language layered on top of the small proxy schema.
- Nickel configuration or a fourth first-class configuration syntax.
- Claims of universal TLS decryption across every language, TLS library, or
  certificate-pinning implementation.

These boundaries keep Heimdall focused on a reliable command wrapper and leave
application-specific inspection to explicit tools and trust decisions.

## How to influence the roadmap

Open an issue with a minimal command, configuration, kernel/runtime details,
and the output of `heimdall agent`. For larger changes, discuss the boundary
and acceptance criteria before opening a pull request. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
