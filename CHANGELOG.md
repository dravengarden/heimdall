# Changelog

All notable changes to Heimdall are documented here. Heimdall is pre-1.0; this
file records release-level changes and does not serve as an API migration
guide.

## [Unreleased]

### Added

- Add a pinned Ubuntu 24.04 x86_64 KVM release gate for native archive
  installation, exact positive and negative setup authorization, fake DNS
  without relaxing AppArmor's user-namespace restriction, direct TCP/UDP
  interception, descendants, all four forwarded owner signals, concurrent
  sessions, parent-death cleanup and log recovery, runtime and relay TLS
  evidence, JSONL integrity, and daemonless cleanup.
- Add a pinned Debian 13 x86_64 KVM release gate that exercises the stock
  nss-myhostname/nss-resolve status-action chain through the private resolver
  mount, the full daemonless archive/lifecycle suite, and strict Python
  3.13/OpenSSL relay verification without requiring a session D-Bus service.
- Add explicit pinned Ubuntu and Debian performance gates that emit the
  existing `heimdall.benchmark/v1` contract for latency, procfs RSS, 1/10/50
  concurrent starts, SOCKS5 TCP/UDP, transport and relay capture throughput,
  and event integrity.
- Add resolver compatibility preflight to `heimdall.agent/v8`, including the
  selected fake-DNS strategy, NSS/nscd evidence, user-namespace settings,
  shell-safe inspection argv, and a stable blocking diagnostic.
- Add relay CA validation to `heimdall.agent/v8`; invalid material now reports
  `config.decrypt.ca_material_error`, makes readiness false, and withholds the
  execution prefix before a command starts.

### Changed

- Include the Ubuntu and Debian compatibility guests in the authoritative local
  release transaction while keeping the broader SOCKS5, fake-DNS, QUIC,
  runtime-client, capture, rotation, retention, and stress matrix in the
  current/Linux 6.6 LTS NixOS guests.
- Generalize the disposable-VM benchmark runner across project-owned client,
  policy, configuration, CA, and RSS backends, and report the distribution,
  guest memory, and RSS source without changing its scenario names.
- Reuse host resolver files when NSS is limited to `files dns`, allowing cgroup
  port-53 interception to provide fake DNS without a user namespace; retain the
  private resolver-mount fallback for NSS modules and caches that bypass DNS.
- Reject a deterministically disabled private resolver namespace before
  creating run state, attaching eBPF, or executing the requested command.
- Generate relay CAs with explicit `keyCertSign`/`cRLSign` usage and intercepted
  leaves with an Authority Key Identifier; reject older incompatible CA
  material during agent and run preflight with a replacement-trust hint.

### Known limitations

- Native aarch64 real-eBPF acceptance still requires an ARM Linux execution
  host and is not yet part of the completed release matrix.

## [0.1.5] - 2026-08-29

### Highlights

- Add an offline, agent-readable schema for low-cardinality run summaries and
  correct payload filtering to select only real content-addressed blobs.
- Apply the same static-binary and embedded-eBPF hygiene gate to native, npm,
  PyPI, and Cargo release artifacts on both Linux architectures.
- Add host-guarded native aarch64 current/Linux 6.6 real-eBPF acceptance
  outputs while keeping the missing ARM execution result explicit.

### Added

- Add native `aarch64-linux` static-package and current/Linux 6.6 LTS
  real-eBPF VM outputs, with a host-guarded
  `just test-vm-native-aarch64` entry point.
- Add a strict offline `heimdall.logs.summary/v1` JSON Schema through
  `heimdall logs schema --summary v1` and advertise the argv action in
  `heimdall agent`.

### Changed

- Remap eBPF and userspace source paths to deterministic `/source` roots and
  strip redundant DWARF from the embedded eBPF object after BTF generation.
- Make Linux archive, npm, PyPI, and Cargo-package acceptance reject private
  paths, build roots, Nix store paths, ELF debug sections, dynamic
  interpreters, and dynamic dependencies while requiring the eBPF BTF/BTF.ext
  sections.
- Update the transitive `chacha20` lock to 0.10.2, replacing the yanked 0.10.1
  release that contained undefined behavior in its SSE2 RNG backend.
- Route Nix Cargo vendoring through crates.io's canonical static download root
  instead of the legacy API route while retaining lockfile checksum
  verification.
- Make `logs query --has-blob` match only non-null content-addressed blob
  references instead of records whose `blob` field is present but null.

### Known limitations

- The native aarch64 VM outputs require an aarch64 Linux execution host. The
  current release infrastructure has not yet produced that current/LTS result,
  so aarch64 remains structurally checked with CLI execution under emulation.

## [0.1.4] - 2026-08-24

### Highlights

- Publish only the user-facing `heimdall-egress` CLI package on crates.io.
- Keep eBPF wire types and configuration parsing as repository-internal crates
  instead of exposing implementation packages as products.
- Preserve one-command `cargo install heimdall-egress --locked` installation
  with the verified eBPF object embedded in the source crate.

### Changed

- Move the canonical shared wire types and configuration schema into the CLI
  source tree, with internal workspace crates reusing those exact files for
  eBPF builds and schema tests.
- Reduce the Cargo Release asset, trusted-publishing workflow, Lasso binding,
  and registry acceptance contract from three crates to `heimdall-egress`.

### Known limitations

- Native macOS support is not available yet.
- Cargo installation compiles the userspace CLI locally and therefore takes
  longer than installing the prebuilt npm, PyPI, or GitHub Release packages.

## [0.1.3] - 2026-08-24

### Highlights

- Publish the official `heimdall` CLI as the `heimdall-egress` source crate,
  with no install-time downloader, lifecycle script, or daemon.
- Preserve local release authority by attaching checksum-verified Cargo
  packages to GitHub Releases and reproducing them before any OIDC upload.
- Add one-time crates.io Trusted Publisher setup so routine releases use a
  short-lived GitHub OIDC credential instead of a stored registry token.

### Added

- Add publishable `heimdall-common`, `heimdall-config`, and `heimdall-egress`
  crates with complete registry metadata and a project-owned crates.io landing
  page.
- Add Cargo package acceptance for archive inventory, metadata, landing-page
  content, and byte equality between the packaged eBPF ELF and its pinned Nix
  build.

### Changed

- Embed the locally verified eBPF object from a versioned crate resource so
  `cargo install heimdall-egress --locked` needs only stable Rust 1.95 and does
  not require an eBPF compiler at installation time.
- Extend the GitHub Release transaction with three `.crate` assets and their
  SHA-256 files. The thin Cargo workflow reproduces those packages from the
  immutable tag before publishing the dependency crates and CLI in order.
- Document Cargo installation, source-package architecture, first-publication
  bootstrap, subsequent OIDC publication, and independent fresh-install
  acceptance.

### Known limitations

- Native macOS support is not available yet.
- Cargo installation compiles the userspace CLI locally and therefore takes
  longer than installing the prebuilt npm, PyPI, or GitHub Release packages.

## [0.1.2] - 2026-08-24

### Highlights

- Publish the official daemonless Heimdall CLI through PyPI for x86_64 and
  aarch64 Linux across glibc and musl systems.
- Keep PyPI packaging local and immutable: each wheel embeds one verified
  release binary and performs no install-time download or build.
- Publish the exact checksum-verified GitHub Release wheels through PyPI OIDC
  with no registry token or second release command.

### Added

- Add the public `heimdall-egress` PyPI distribution with `heimdall` and
  `heimdall-egress` console commands, Python 3.9+ metadata, `pipx.run` support,
  and project-owned install, architecture, mode, and security documentation.
- Add native wheel acceptance for metadata rendering, checksums, x86_64
  installation and execution, bundled-path discovery, static linkage, and
  aarch64 architecture integrity.

### Changed

- Extend `just release-github` to build and verify the two PyPI wheels locally,
  attach them and their checksums to the GitHub Release, and let the thin
  `publish-pypi.yml` workflow upload only those immutable assets with pinned
  `uv` and GitHub OIDC.
- Document persistent and ephemeral installation through `uv`, `pip`, and
  `pipx`, including the stable native-path authorization boundary required by
  real proxy sessions.

### Known limitations

- Native macOS support is not available yet.
- Native aarch64 real-eBPF VM acceptance remains future work; the aarch64 wheel
  is checked for architecture, static linkage, metadata, and checksum integrity.

## [0.1.1] - 2026-08-24

### Highlights

- Publish the official daemonless Heimdall CLI through npm for x86_64 and
  aarch64 Linux with no install lifecycle scripts.
- Make npm publication consume the exact locally verified GitHub Release asset
  through GitHub OIDC instead of a long-lived registry token.
- Expand the npm package page with verified install and one-shot commands,
  quick start, architecture, operating modes, and security boundaries.

### Added

- Add the public `heimdall-egress` npm distribution with embedded x86_64 and
  aarch64 Linux musl binaries, `heimdall` and `heimdall-egress` launchers, no
  install lifecycle scripts, and local global-install/`npm exec` acceptance.

### Changed

- Expand the npm package page with npm, pnpm, Yarn, Bun, and Deno install and
  one-shot commands plus concise setup, architecture, operating-mode, platform,
  daemonless lifecycle, and security guidance.
- Build the exact npm tarball locally with pinned npm 12 and attach it and its
  checksum to the GitHub Release. Publishing the Release triggers the
  project-owned workflow, whose native npm CLI uses OIDC without a long-lived
  write token or a second release command.
- Require curated GitHub Release notes generated from each version's
  highlights, structured changelog, known limitations, installation and
  artifact details, local verification evidence, and full comparison link.

### Removed

- Remove the legacy authenticated local `npm publish` transaction. npm
  versions now derive only from checksum-verified GitHub Release assets.
- Remove the GitHub Actions Linux CI workflow. Source, package, and current/6.6
  LTS real-eBPF gates remain local (`just verify`, `just test-package`,
  `just test-vm`); `just release-github` reruns them locally before creating
  the tag and publishing its archives and checksums.

### Known limitations

- Native macOS support is not available yet.

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
