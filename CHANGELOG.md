# Changelog

All notable changes to heimdall are documented here.

## [Unreleased]

### Changed

- Reframed heimdall as a proxychains-style command wrapper.
- Made unregistered cgroups bypass the relay by default; only commands started
  through `heimdall run` are redirected.
- Replaced the orchestrator-shaped schema with one small format-independent
  model containing `proxies`, `run`, and optional `daemon` settings.
- Added strict TOML, YAML, JSON, and Nickel decoding, including ambiguous-file,
  unknown-field, reference, address, listener, path, and CIDR validation.
- Rebuilt the bundled Heimdall skill around the command-wrapper workflow and
  the live CLI contract.
- Added `heimdall agent`, a side-effect-free versioned JSON preflight with
  stable error codes, readiness exit codes, decisions, and argv arrays.
- Renamed the daemon subcommand for a clearer CLI surface.
- Simplified `heimdall run` to `--proxy`, `--dns`, and the wrapped command.

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
