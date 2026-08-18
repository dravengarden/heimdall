---
type: docs_index
description: Heimdall CLI proxy, daemonless runtime and agent event-log designs, strict configuration, roadmap, and operations documentation.
---

# Documentation index

## Scope

Heimdall CLI proxy, daemonless runtime and agent event-log designs, strict
configuration, roadmap, and operations documentation. The index distinguishes
stable contracts, planning, design material, and operational guidance.

## Reading order

- [`README.md`](../README.md) — Project overview and quick start
- [`ROADMAP.md`](../ROADMAP.md) — Public status, active development tracks, planned macOS support, and non-goals
- [`architecture.md`](architecture.md) — CLI, transactional eBPF lifecycle, map-selected relay endpoint, DNS, fail-closed UDP correlation, capture, and verified runtime/relay TLS boundaries
- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Foreground per-run architecture and implementation status for session-owned data-plane and kernel resources
- [`design/agent-event-log.md`](design/agent-event-log.md) — Phase 1 JSONL/run schemas and CLI plus planned blobs and daemonless ownership
- [`runbook.md`](runbook.md) — Runbook

## Documents

### Core documents

- [`README.md`](../README.md) — Project overview and quick start
- [`ROADMAP.md`](../ROADMAP.md) — Public status, planned macOS wrapper/Network Extension backends, and roadmap
- [`architecture.md`](architecture.md) — CLI, eBPF, DNS, TCP/UDP relay, and TLS decrypt boundaries
- [`config.md`](config.md) — Strict TOML/YAML/JSON policy rules, credentials, capture/decrypt modes, and UDP/QUIC limits
- [`runbook.md`](runbook.md) — Build, agent and capture contracts, runtime and lifecycle matrices, safe eBPF cleanup, TLS capture, stress, and dual-stack HTTP/3 VM acceptance

### Design documents

- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Accepted replacement for the persistent daemon; target-driven attach and unpinned process ownership are implemented, while setup handoff remains in development
- [`design/agent-event-log.md`](design/agent-event-log.md) — Agent-first event storage and CLI contract; lifecycle and TCP/UDP metadata are implemented in Phase 1
- [`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md) — Agent-facing schema map and safe parsing rules
