# Changelog

All notable changes to Heimdall are documented here. Heimdall is pre-1.0; this
file records release-level changes and does not serve as an API migration
guide.

## [Unreleased]

### Changed

- Require curated GitHub Release notes generated from each version's
  highlights, structured changelog, known limitations, installation and
  artifact details, local verification evidence, and full comparison link.

### Removed

- Remove the GitHub Actions Linux CI workflow. Source, package, and current/6.6
  LTS real-eBPF gates remain local (`just verify`, `just test-package`,
  `just test-vm`); `just release-github` reruns them locally before creating
  the tag and publishing its archives and checksums.

## [0.1.0] - 2026-08-21

### Added

- Add reproducible static x86_64 and aarch64 Linux release archives, SHA-256
  checksums, authoritative local release gates, atomic installation, one-level
  rollback, and tagged GitHub release automation. Packaging acceptance rejects
  dynamic dependencies on both architectures, exercises the aarch64 CLI under
  emulation, and exercises native install, upgrade, and rollback on x86_64.
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
- Derive bounded HTTP/1 request and response header records from explicit TLS
  plaintext, link them to source event sequences, and mask common credential
  headers without copying bodies into JSONL.
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
- Add real-eBPF disposable NixOS VM acceptance on current and Linux 6.6 LTS
  kernels for dual-stack TCP/UDP, fake and system DNS, QUIC, common CLI/runtime
  clients, concurrent runs, both TLS paths, log rotation, fail-closed errors,
  and complete cleanup.
- Add `heimdall logs summary` with the stable
  `heimdall.logs.summary/v1` low-cardinality run-health contract, plus a
  repeatable current/6.6 LTS real-eBPF VM benchmark for latency, RSS, 1/10/50
  concurrent cold starts, sustained direct/proxied TCP, proxied UDP,
  transport-capture and relay-plaintext-capture throughput, and event-integrity
  checks.
- Distinguish relay TLS upstream certificate verification failures,
  downstream certificate alerts, and downstream closes without TLS
  `close_notify`, with stable codes, phases, peer-verification state, and
  matching flow-close evidence.
- Report a verified upstream's client-certificate requirement as
  `tls_upstream_client_auth_required`, and cover long-lived multi-exchange relay
  streams without claiming relay compatibility with client-certificate mTLS.
- Prove retention apply removes exactly the dry-run candidates while preserving
  the newest run, and document that pruning is explicit and daemonless.
- Report the relay CA's DER SHA-256 from both `tls init-ca` and `heimdall agent`
  so agents can verify command-scoped client trust without exposing the key.
- Require source, static package, and current/6.6 LTS real-eBPF gates to pass
  locally before a tagged release can be published.
- Add offline `heimdall config schema` and read-only `config example` commands,
  generated from the canonical Rust/Serde model and shared init templates.

### Fixed

- Keep Unix-socket tests below Linux `SUN_LEN` even when CI supplies a deeply
  nested `TMPDIR`.
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
