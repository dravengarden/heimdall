# Changelog

All notable changes to Heimdall are documented here. Heimdall is pre-1.0; this
file describes the current unreleased contract and does not serve as an API
migration guide.

## [Unreleased]

### Added

- Add one foreground Linux execution path for every decrypt mode. Each run
  owns isolated relay and DNS listeners, cgroup, unpinned maps, FD-owned links,
  event state, and a strict `heimdall.setup/v2` helper that drops privilege
  before the wrapped command starts.
- Keep the unprivileged setup helper for the session as a parent-death guard.
  Unexpected owner exit kills and removes the command cgroup before surviving
  descendants can continue without interception.
- Add `heimdall.agent/v7`, a read-only single-document JSON preflight with
  selected foreground ownership, capability evidence, stable diagnostics, and
  shell-safe argv actions.
- Add per-run `heimdall.run/v1` manifests and ordered `heimdall.event/v1`
  JSONL lifecycle/TCP/UDP evidence with bundled schemas, writer-owned rotation,
  integrity verification, retention, and `heimdall logs` workflows.
- Add bounded private payload capture under `heimdall.capture/v1` with an
  explicit opaque-transport or TLS-plaintext boundary.
- Add explicit `off`, `runtime`, and `relay` TLS modes. Runtime mode observes
  startup-discovered OpenSSL APIs without changing trust; relay mode validates
  upstream TLS and issues per-host leaves from invoking-user-owned CA material.
- Add real-eBPF disposable NixOS VM acceptance for dual-stack TCP/UDP, fake and
  system DNS, QUIC, common CLI/runtime clients, concurrent runs, both TLS paths,
  log rotation, fail-closed errors, and complete cleanup.

### Fixed

- Keep policy enforcement active until every descendant leaves the command
  cgroup, and preserve command exit and signal status.
- Preserve the resolved global configuration and exact argv across delegated
  `systemd-run --user --scope` re-entry.
- Fail runtime TLS startup when no supported OpenSSL image can be attached;
  capture only bytes reported as transferred by supported OpenSSL APIs.
- Normalize IPv4-mapped destinations and preserve fake-DNS host identity for
  dual-stack clients.
- Use socket-and-destination tokens for IPv4 UDP and guarded identity for IPv6
  UDP so concurrent and connectionless flows cannot overwrite peer ownership.
- Bound SOCKS5 setup, validate replies and credentials strictly, and fail
  unsupported or ambiguous network shapes closed.
- Allocate relay and fake-DNS ports per run and return to the pre-run BPF-link
  baseline after normal completion or parent death.

### Changed

- Define `docs/product-contract.md` as the normative summary for lifecycle,
  network, TLS, agent evidence, optional UI, and platform boundaries.
- Keep one strict format-independent configuration model across TOML, YAML,
  and JSON, with unknown fields and invalid enum values rejected directly.
- Keep payload evidence explicitly separate from metadata events through the
  `heimdall.capture/v1` contract.
