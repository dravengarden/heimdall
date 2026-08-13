# Changelog

All notable changes to heimdall are documented here.

## [Unreleased]

### Fixed

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

- Added real HTTP/3 with QUIC Retry and multi-request acceptance, IPv4 UDP
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
  all four starter formats are now tested through the same canonical loader.
- Made unsupported connectionless UDP fail closed, removed implicit address bypasses
  from registered cgroups, completed fake DNS over TCP as well as UDP, and made DNS
  plus control-listener binding fail before daemon readiness.
- Reframed heimdall as a proxychains-style command wrapper.
- Made unregistered cgroups bypass the relay by default; only commands started
  through `heimdall run` are redirected.
- Replaced the orchestrator-shaped schema with one format-independent model.
- Added strict TOML, YAML, JSON, and Nickel decoding, including ambiguous-file,
  unknown-field, reference, address, listener, path, and CIDR validation.
- Rebuilt the bundled Heimdall skill around the command-wrapper workflow and
  the live CLI contract.
- Added `heimdall agent`, a side-effect-free versioned JSON preflight with
  stable error codes, readiness exit codes, decisions, and argv arrays.
- Renamed the daemon subcommand for a clearer CLI surface.
- Simplified `heimdall run` to `--policy` and the wrapped command.

### Removed

- Cluster integration and its vocabulary.
- Workload selector routing from the public configuration.
- The bundled Web UI and its Deno/Vite/Nix build path.
- The `flows` command from the primary CLI surface.
- Orchestrator-style version and kind configuration fields.

## Pre-history

The alpha began as a broader transparent egress and TLS observability
experiment. It gained cgroup eBPF redirection, fake-IP DNS, dual-stack SOCKS5,
flow storage, and TLS probes before narrowing to the command-wrapper use case.
