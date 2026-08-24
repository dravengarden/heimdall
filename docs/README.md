# Documentation

- [../ROADMAP.md](../ROADMAP.md) — project status, active development, and non-goals
- [product-contract.md](product-contract.md) — normative product, lifecycle, network, TLS, evidence, UI, and platform requirements
- [architecture.md](architecture.md) — foreground CLI/setup-worker boundary and data path
- [design/daemonless-runtime.md](design/daemonless-runtime.md) — implemented foreground per-run path for proxying and both TLS modes
- [design/agent-event-log.md](design/agent-event-log.md) — JSONL events, content-addressed payload blobs, run manifests, rotation, retention, and agent CLI
- [config.md](config.md) — the strict TOML/YAML/JSON configuration
- [install.md](install.md) — native, npm, PyPI, and Cargo Linux releases, checksum verification, setup authorization, upgrade, and rollback
- [runbook.md](runbook.md) — build, agent JSON contract, lifecycle, and troubleshooting
- [releasing.md](releasing.md) — curated changelog, local release assets, release-triggered npm/PyPI/crates.io OIDC publication, and verification standard

Agent workflows live in [`../skills/heimdall/`](../skills/heimdall/). The
event schema map is
[`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md).
