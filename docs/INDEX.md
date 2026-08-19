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
- [`product-contract.md`](product-contract.md) — Normative product, lifecycle, network, TLS, agent evidence, optional UI, and platform requirements
- [`ROADMAP.md`](../ROADMAP.md) — Public status, active development tracks, planned macOS support, and non-goals
- [`architecture.md`](architecture.md) — Foreground CLI ownership, setup privilege drop, per-run eBPF/relay/DNS lifecycle, fail-closed UDP correlation, capture, and TLS boundaries
- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Foreground per-run architecture and implementation status for session-owned data-plane and kernel resources
- [`design/agent-event-log.md`](design/agent-event-log.md) — Daemonless Phase 1 JSONL/run schemas and CLI plus planned blobs
- [`runbook.md`](runbook.md) — Runbook

## Documents

### Core documents

- [`README.md`](../README.md) — Project overview and quick start
- [`product-contract.md`](product-contract.md) — Single normative statement of the current product contract
- [`ROADMAP.md`](../ROADMAP.md) — Public status, planned macOS wrapper/Network Extension backends, and roadmap
- [`architecture.md`](architecture.md) — CLI, eBPF, DNS, TCP/UDP relay, and TLS decrypt boundaries
- [`config.md`](config.md) — Strict TOML/YAML/JSON policy rules, credentials, capture/decrypt modes, and UDP/QUIC limits
- [`runbook.md`](runbook.md) — Build, narrow setup authorization, agent/log contracts, daemonless operation, TLS capture, and VM acceptance

### Design documents

- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Implemented foreground replacement for all decrypt modes, including startup-discovered OpenSSL probes
- [`design/agent-event-log.md`](design/agent-event-log.md) — Agent-first event storage and CLI contract; lifecycle and TCP/UDP metadata are implemented in Phase 1
- [`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md) — Agent-facing schema map and safe parsing rules
