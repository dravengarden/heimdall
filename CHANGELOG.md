# Changelog

All notable changes to Heimdall are documented here. Heimdall is pre-1.0; this
file describes the current unreleased contract and does not serve as an API
migration guide.

## [Unreleased]

### Added

- Add reproducible static x86_64 Linux release archives, SHA-256 checksums,
  atomic installation, one-level rollback, and tagged GitHub release
  automation. Packaging acceptance rejects dynamic dependencies and exercises
  install, upgrade, and rollback.
- Add one foreground Linux execution path for every decrypt mode. Each run
  owns isolated relay and DNS listeners, cgroup, unpinned maps, FD-owned links,
  event state, and a strict `heimdall.setup/v2` helper that drops privilege
  before the wrapped command starts.
- Keep the unprivileged setup helper for the session as a parent-death guard.
  Unexpected owner exit kills and removes the command cgroup before surviving
  descendants can continue without interception.
- Add `heimdall.agent/v8`, a read-only single-document JSON preflight with
  selected foreground ownership, capability evidence, stable diagnostics, and
  shell-safe argv actions.
- Add per-run `heimdall.run/v1` manifests and ordered `heimdall.event/v1`
  JSONL lifecycle/TCP/UDP evidence with bounded content-addressed payload
  blobs, payload-aware filters, byte/age rotation, integrity verification,
  retention, and `heimdall logs` workflows.
- Add correlated fake-DNS query/answer records, ordered TCP/UDP policy
  decisions, explicit OpenSSL runtime-observation records, parsed relay
  ClientHello records, and negotiated relay TLS evidence.
- Publish blobs atomically, verify an existing digest before reuse, and return
  stable `event_store_full` or `event_store_permission_denied` failures.
- Validate every run manifest and event record against the bundled offline
  Draft 2020-12 schemas during `heimdall logs verify`.
- Add payload boundary/direction allowlists and environment-backed exact-value
  redaction that masks bytes before content hashing and blob publication.
- Coalesce payload reads into size- and latency-bounded per-direction blocks
  with explicit block indexes and flush reasons in `flow.data`.
- Add dry-run-first recovery for orphaned runs that preserves the original
  manifest and incomplete tail without inventing a close event.
- Forward foreground-owner signals to the wrapped command while retaining the
  owner for cleanup, and make setup authorization explicitly non-interactive.
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
- Keep JSONL directly usable by Linux tools while storing binary payloads once
  under the run's SHA-256 blob tree; remove the legacy per-flow capture files.
