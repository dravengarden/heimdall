# Documentation

- [../ROADMAP.md](../ROADMAP.md) — project status, active development, and non-goals
- [product-contract.md](product-contract.md) — normative product, lifecycle, network, TLS, evidence, UI, and platform requirements
- [architecture.md](architecture.md) — foreground CLI/setup-worker boundary, shared outbound relay transport, and backend-owned data path
- [design/daemonless-runtime.md](design/daemonless-runtime.md) — implemented foreground per-run path for proxying and both TLS modes
- [design/agent-event-log.md](design/agent-event-log.md) — portable JSONL owner and offline CLI, events, content-addressed payload blobs, run manifests, rotation, and retention
- [design/macos-backend.md](design/macos-backend.md) — native-accepted Apple-silicon cooperative TCP source backend, active interpose fallback direction, native package boundary, and deferred Network Extension prototype
- [design/macos-fallbacks.md](design/macos-fallbacks.md) — proxychains-ng, Proxyman, mitmproxy, PF/TUN, and Network Extension research with the selected daemonless fallback architecture and acceptance plan
- [design/macos-control-protocol.md](design/macos-control-protocol.md) — deferred Rust/Swift authenticated Network Extension run-registration research and native attribution evidence gate
- [config.md](config.md) — the strict TOML/YAML/JSON configuration
- [install.md](install.md) — native, npm, PyPI, and Cargo Linux releases, artifact hygiene, compatibility, checksum verification, setup authorization, upgrade, and rollback
- [runbook.md](runbook.md) — build, Darwin all-targets plus native Apple-silicon explicit/interpose-feasibility/deferred-companion/package gates, x86_64 NixOS/Ubuntu/Debian functional and performance VM gates, native-aarch64 acceptance, agent JSON contract, lifecycle, and troubleshooting
- [releasing.md](releasing.md) — curated changelog, Linux/macOS artifact hygiene, Developer ID/notarization and native-ARM claims, local release assets, registry OIDC publication, and verification standard

Agent workflows live in [`../skills/heimdall/`](../skills/heimdall/). The
event schema map is
[`../skills/heimdall/references/events.md`](../skills/heimdall/references/events.md).
