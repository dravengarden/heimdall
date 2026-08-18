# Documentation

- [../ROADMAP.md](../ROADMAP.md) — project status, active development, and non-goals
- [architecture.md](architecture.md) — foreground CLI/setup-worker boundary and data path
- [design/daemonless-runtime.md](design/daemonless-runtime.md) — implemented foreground per-run path and remaining runtime-TLS compatibility boundary
- [design/agent-event-log.md](design/agent-event-log.md) — Phase 1 JSONL events, run manifests, rotation, retention, and agent CLI, with payload blobs planned
- [config.md](config.md) — the strict TOML/YAML/JSON configuration
- [runbook.md](runbook.md) — build, agent JSON contract, health, and troubleshooting

Agent workflows live in [`../skills/heimdall/`](../skills/heimdall/). The
event schema map is
[`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md).
