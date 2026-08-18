# Changelog

All notable changes to heimdall are documented here.

## [Unreleased]

### Added

- Add Phase 1 of the agent-first event store: every `heimdall run` writes a
  user-owned `heimdall.run/v1` manifest and ordered `heimdall.event/v1` JSONL
  lifecycle/TCP/UDP metadata, with bundled schemas, writer-owned rotation, digest
  verification, retention preview/apply, and `logs` discovery/query/tail
  commands. Payload capture remains on the existing explicit
  `heimdall.capture/v1` boundary.

- Add strict `runtime` and `relay` TLS decrypt modes. Runtime mode
  observes registered OpenSSL clients without changing trust; relay mode
  verifies upstream TLS, mirrors ALPN, issues per-host leaves from an explicit
  protected CA, preserves non-TLS passthrough, and captures plaintext.
- Add `heimdall tls init-ca --json` plus `heimdall.agent/v4` decrypt
  capabilities and repair argv for agent-driven setup.
- Add `heimdall.daemon.health/v2` to the loopback health endpoint and embed it
  in the agent report, including the active decrypt mode and runtime probe
  attachment counts.

### Fixed

- Capture only the bytes that successful OpenSSL read/write calls actually
  transferred, including the `SSL_read_ex` and `SSL_write_ex` APIs. Runtime
  startup now fails when no loaded OpenSSL image can be attached instead of
  claiming readiness without plaintext coverage.
- Exercise both OpenSSL runtime capture and relay TLS termination against a
  real trusted TLS server in the disposable eBPF acceptance VM.
- Version pinned map layouts, replace cgroup programs as one rollback-capable
  transaction, and add a machine-readable eBPF cleanup command that refuses
  daemon or active-workload races.
- Keep registered cgroups intercepted across daemon restarts with pinned eBPF
  maps and atomic link updates. Traffic fails closed while the relay is
  unavailable; existing relay sessions and connections remain unsupported. The
  first upgrade from a release without pinned links still requires one ordinary
  restart to install them.
- Restore active CLI cgroup policies and fake-DNS hostname mappings after a
  daemon service restart. Runtime state is atomic, strict, and root-only; stale
  registrations are removed during recovery. Existing connections remain
  explicitly unsupported.
- Keep a command policy registered until every descendant exits its cgroup,
  preventing background children from losing proxy enforcement when their
  immediate parent finishes. Disable `systemd-run` environment expansion so
  structured argv containing `$` reaches the wrapped command unchanged.
- Normalize IPv4-mapped destinations intercepted by `connect6`, preserving
  fake-DNS hostname recovery and transparent peer identity for runtimes such as
  Java that use dual-stack IPv6 sockets for IPv4 answers.
- Reject ambiguous native IPv6 UDP multi-target sends and duplicate explicit
  source-port binds instead of overwriting relay ownership and risking a
  response with the wrong peer identity. Socket release now frees that
  ownership for safe port reuse.
- Support common dual-stack UDP clients that send to IPv4-mapped destinations
  through an IPv6 socket, including HTTP/3/QUIC, while restoring peer identity.
- Correlate IPv4 UDP by socket and destination token, preserving source
  identity for connectionless multi-target traffic and concurrent
  `SO_REUSEPORT` sockets instead of relying on an ambiguous source port.
- Prevent IPv4 and IPv6 relay correlations from overwriting each other when
  both sockets reuse the same ephemeral source port.
- Preserve `dns = "system"` and literal-IP semantics by treating TLS as opaque
  payload instead of rewriting destinations from ClientHello SNI. SOCKS5
  connection setup now has bounded timeouts, strict reply/domain/credential
  validation, and downgrade-resistant username/password negotiation. Fake-IP
  pools no longer recycle addresses into potentially stale application caches.

### Changed

- Rename decrypt modes by execution boundary: `transparent` becomes `runtime`
  and `mitm` becomes `relay`. The breaking machine-readable names are published
  through `heimdall.agent/v4`, `heimdall.daemon.health/v2`,
  `heimdall.config.validate/v2`, and `heimdall.tls-ca/v2`.
- Added opt-in, bounded TCP and UDP relay capture as root-only
  `heimdall.capture/v1` JSONL files. Capture covers direct and SOCKS5 actions,
  records its payload boundary explicitly, fails affected flows on write errors, and exposes its
  exact boundary through `heimdall agent`.
- Added real-eBPF acceptance for an active fake-DNS command across a daemon
  restart and exposed policy recovery, DNS recovery, connection survival, and
  uninterrupted-continuity boundaries separately through `heimdall agent`.
- Added real-eBPF lifecycle acceptance for Git, exit and signal propagation,
  background descendants, unavailable-daemon pre-exec failure, and
  unreachable-upstream fail-closed behavior. Exposed the results and the
  unsupported daemon-restart continuity boundary through `heimdall agent`.
- Added real cgroup eBPF acceptance for static Go `netgo`, Java, Node.js, and
  Rust across fake-DNS TCP plus connected IPv4 and IPv6 UDP, and exposed the
  tested matrix through `heimdall agent`.
- Added real IPv4 and native IPv6 HTTP/3 with QUIC Retry and multi-request
  acceptance, IPv4 UDP
  token stress across 128 destinations, 32 concurrent `SO_REUSEPORT` sockets,
  and `sendmmsg`/`recvmmsg` coverage.
- Reused one bidirectional direct or SOCKS5 UDP association per connected
  socket, added multi-response delivery, socket/cgroup-aware cleanup, bounded
  queues and sessions, and machine-readable payload and QUIC limits.
- Added strict UDP routing through SOCKS5 UDP ASSOCIATE or direct
  egress, UDP-aware `config explain`, transparent `getpeername`, and explicit
  machine-readable per-family capability limits. IPv6 supports a single-peer
  fallback while ambiguous multi-target and same-port concurrency fail closed.
- Replaced `proxies` and per-run DNS overrides with named SOCKS5 outbounds and
  command-selected policies containing ordered TCP/UDP rules and explicit
  `route`, `direct`, or `reject` final actions.
- Added aggregated configuration diagnostics with stable codes, JSON paths,
  and repair hints plus `config explain` for deterministic rule inspection;
  all three starter formats are now tested through the same canonical loader.
- Made unsupported connectionless UDP fail closed, removed implicit address bypasses
  from registered cgroups, completed fake DNS over TCP as well as UDP, and made DNS
  plus control-listener binding fail before daemon readiness.
- Reframed heimdall as a proxychains-style command wrapper.
- Made unregistered cgroups bypass the relay by default; only commands started
  through `heimdall run` are redirected.
- Replaced the orchestrator-shaped schema with one format-independent model.
- Added strict TOML, YAML, and JSON decoding, including ambiguous-file,
  unknown-field, reference, address, listener, path, and CIDR validation.
- Rebuilt the bundled Heimdall skill around the command-wrapper workflow and
  the live CLI contract.
- Added `heimdall agent`, a side-effect-free versioned JSON preflight with
  stable error codes, readiness exit codes, decisions, and argv arrays.
- Renamed the daemon subcommand for a clearer CLI surface.
- Simplified `heimdall run` to `--policy` and the wrapped command.

### Removed

- Nickel configuration and its runtime/package dependency, leaving the three
  direct Serde formats: TOML, YAML, and JSON.
- Cluster integration and its vocabulary.
- Workload selector routing from the public configuration.
- The bundled Web UI and its Deno/Vite/Nix build path.
- The `flows` command from the primary CLI surface.
- Orchestrator-style version and kind configuration fields.

## Pre-history

The alpha began as a broader transparent egress and TLS observability
experiment. It gained cgroup eBPF redirection, fake-IP DNS, dual-stack SOCKS5,
flow storage, and TLS probes before narrowing to the command-wrapper use case.
