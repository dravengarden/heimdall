---
name: heimdall
description: Operate and configure the Heimdall proxychains-style CLI wrapper. Use when an agent needs to run a command through a named SOCKS5 proxy, create or strictly validate Heimdall TOML/YAML/JSON/Nickel configuration, inspect daemon health, diagnose command-scoped proxying or fake-IP DNS, or work with heimdall.service and /etc/heimdall/config.*.
---

# Heimdall

Treat Heimdall as a command wrapper, not a host-wide traffic router. The daemon
redirects only cgroups registered by `heimdall run`; unrelated processes bypass
it.

## Start with the live interface

Run this first:

```bash
heimdall agent
```

Parse its single `heimdall.agent/v1` JSON object. Exit 0 means ready; exit 1
means the JSON explains why. Read `config.error.code` or `decision.error.code`
before the human-readable message. Execute `actions` as argv arrays; never join
or evaluate them as a shell string.

Use the human command tree only when deeper discovery is needed:

```bash
heimdall help -v
heimdall config path
heimdall config validate --json
heimdall status --json
```

Use the installed CLI output as the authority for available flags. Do not infer
removed workload-routing, flow-query, UI, or TLS-observability commands.

## Route a command

Preview readiness and selection before execution when changing proxy or DNS:

```bash
heimdall agent -p <proxy> --dns fake
heimdall run -p <proxy> -- curl https://example.com
```

Omit `-p` and `--dns` to use the config's `run` defaults. Keep the command after
`--`. Read [references/commands.md](references/commands.md) for diagnostics and
the daemon boundary.

## Edit configuration safely

Keep exactly one `/etc/heimdall/config.{toml,yaml,yml,json,ncl}` file unless an
explicit `--config` path is used. All formats decode into one strict schema;
unknown fields, wrong types, bad references, malformed addresses, invalid
listener collisions, unsafe cgroup paths, and malformed CIDRs are rejected.

After every edit, run:

```bash
heimdall config validate --json
heimdall agent
```

Read [references/config.md](references/config.md) before creating or changing a
config. Never put a password directly in config; use an absolute `passwordFile`.

## Preserve the ownership boundary

- Do not change routing, firewall, DNS, or system-wide proxy state merely to use
  Heimdall.
- Do not start the privileged daemon when the user asked only for config review.
- Treat a successful config check as syntax and semantics proof, not daemon or
  network acceptance.
- For runtime failures, collect `heimdall agent`, `heimdall status --json`, and recent
  `heimdall.service` logs before proposing a change.
