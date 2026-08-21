---
type: docs_index
description: Heimdall CLI proxy, daemonless runtime, agent event-log and sustained performance baseline designs including derived HTTP evidence, strict configuration, roadmap, and operations documentation.
---

# Documentation index

## Scope

Heimdall CLI proxy, daemonless runtime, agent event-log and sustained
performance baseline designs including derived HTTP evidence, strict
configuration, roadmap, and operations documentation. The index distinguishes
stable contracts, planning, design material, and operational guidance.

## Reading order

- [`README.md`](../README.md) — Project overview and quick start
- [`product-contract.md`](product-contract.md) — Normative product, lifecycle, network, TLS, capture safety, agent evidence, optional UI, and platform requirements
- [`ROADMAP.md`](../ROADMAP.md) — Public status, active development tracks, release artifact hygiene, native ARM acceptance, planned macOS support, and non-goals
- [`architecture.md`](architecture.md) — Foreground CLI ownership, setup privilege drop, per-run eBPF/relay/DNS lifecycle, fail-closed UDP correlation, capture, and TLS boundaries
- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Foreground per-run architecture and implementation status for session-owned data-plane and kernel resources
- [`design/agent-event-log.md`](design/agent-event-log.md) — Daemonless JSONL/run schemas, DNS/policy/TLS evidence, content-addressed blobs, rotation, orphan recovery, and CLI
- [`install.md`](install.md) — Native and npm `heimdall-egress` static Linux installation, narrow setup authorization, upgrade, and one-level rollback
- [`runbook.md`](runbook.md) — Runbook
- [`releasing.md`](releasing.md) — Curated changelog, GitHub/npm release, local gate, artifact, and post-publication verification standard

## Documents

### Core documents

- [`README.md`](../README.md) — Project overview and quick start
- [`product-contract.md`](product-contract.md) — Single normative statement of the current product contract
- [`ROADMAP.md`](../ROADMAP.md) — Public status, release artifact hygiene and native ARM work, planned macOS wrapper/Network Extension backends, and roadmap
- [`architecture.md`](architecture.md) — CLI, eBPF, DNS, TCP/UDP relay, and TLS decrypt boundaries
- [`config.md`](config.md) — Generated offline schema/examples, strict TOML/YAML/JSON policy rules, credentials, capture allowlists/redaction, decrypt modes, and UDP/QUIC limits
- [`install.md`](install.md) — Reproducible native/npm `heimdall-egress` x86_64/aarch64 Linux artifacts, checksums, install ownership, upgrade, and rollback
- [`runbook.md`](runbook.md) — Build, narrow setup authorization, agent/log contracts, capture readiness, daemonless operation, TLS, current/LTS kernel VM acceptance, and performance baseline
- [`releasing.md`](releasing.md) — Required release body, changelog sections, local GitHub/npm publication transactions, platform artifacts, and post-publication verification

### Design documents

- [`design/daemonless-runtime.md`](design/daemonless-runtime.md) — Implemented foreground replacement for all decrypt modes, including startup-discovered OpenSSL probes
- [`design/agent-event-log.md`](design/agent-event-log.md) — Agent-first event storage and CLI contract with lifecycle, DNS/policy/TLS observations, provenance-linked HTTP/1 headers, payload allowlists/redaction, content-addressed blobs, and orphan recovery
- [`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md) — Agent-facing schema map and safe parsing rules
