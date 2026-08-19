---
name: heimdall
description: Operate and configure the Heimdall command-scoped TCP/UDP proxy and TLS inspection wrapper. Use when an agent needs to run one command through a named policy, repair strict TOML/YAML/JSON config, query Heimdall JSONL evidence, or diagnose foreground eBPF and TLS setup.
---

# Heimdall

Treat Heimdall as a command wrapper, not a host-wide router. A normal run
attaches eBPF only to its transient command cgroup and owns its relay, DNS,
maps, links, and logs in the foreground.

Treat [`../../docs/product-contract.md`](../../docs/product-contract.md) as the
normative product boundary. This skill supplies operating procedure and must
not broaden that contract.

## Start with the machine contract

Run:

```bash
heimdall agent
```

Parse the single `heimdall.agent/v7` JSON object. Exit 0 means ready, exit 1
means the document explains why, and exit 2 is invalid CLI usage. Read stable
error `code` values before messages. Execute `actions` as argv arrays; never
join or evaluate them as shell text.

Use `execution` before running a command:

- Require `backend = linux-ebpf-foreground`, `daemon_required = false`,
  `owner = heimdall-run`, and
  `privilege_setup = sudo-then-unprivileged-session-helper` for every decrypt
  mode. Heimdall has no persistent daemon or health endpoint.
- `web_ui_required` must remain false for every executable path.

Use `heimdall help -v` only when deeper command discovery is needed.

## Select evidence boundaries

Read [references/events.md](references/events.md) before consuming run logs.
Phase 1 `heimdall.event/v1` records lifecycle and TCP/UDP metadata in
user-owned JSONL. Use `heimdall logs schema`, `list`, `path`, `query`, `tail`,
`rotate`, and `verify`; standard `jq`, `rg`, `sed`, `sort`, and `wc` are valid
consumers. Do not require or start a Web UI.

If capture is requested, inspect `config.capture`, `config.decrypt`,
`capabilities.capture`, and `capabilities.decrypt`. Require capture `mode: on`
and a suitable byte limit before either decrypt mode. Only an explicit
`tls_plaintext.*` boundary is plaintext evidence; never infer it from port,
SNI, process, or byte shape.

Choose `relay` only with authority to install local trust. Require
`ca_material_ready`, trust only the public `ca_cert`, keep `ca_key` mode 0600
and readable only by the invoking user, and reject pinned or client-certificate
mTLS workflows.

Choose `runtime` only when the client uses a reported OpenSSL API. Ensure a
representative `libssl` image is already mapped when the run starts; the
  setup helper fails before exec if no image can be attached. It drops
  privilege before the workload starts and exits with the run. It changes no
  trust and can coexist with pinning/mTLS, but later-loaded or absent
libraries and APIs have no plaintext guarantee.

## Validate and repair configuration

Read [references/config.md](references/config.md) before creating or changing a
config. Keep exactly one discovered
`/etc/heimdall/config.{toml,yaml,yml,json}` unless global `--config` is
explicit.

After every edit, run:

```bash
heimdall config validate --json
```

Process every diagnostic using `code` for control flow, `path` to locate the
field, and `hint` as the repair constraint. Repeat until `valid` is true. Never
silently replace `route` with `direct`, and never put a password value in the
config; use an absolute `password_file`.

Preview ordered policy decisions before execution:

```bash
heimdall config explain --policy <policy> --domain example.com --port 443 --json
heimdall config explain --policy <policy> --network udp --domain example.com --port 443 --json
heimdall agent --policy <policy>
```

Config validity is not connectivity evidence.

## Check protocol evidence

Before choosing UDP, inspect `capabilities.udp`. IPv4 supports connectionless
multi-target traffic and concurrent sockets sharing one source port. IPv6
supports connected traffic and one peer per connectionless socket, including
IPv4-mapped destinations, but not multi-target or duplicate explicitly bound
ports. Branch on family-specific fields. Respect
`max_socks5_payload_bytes`; `quic_ipv4` and `quic_ipv6` cover single-family
paths only while `quic_address_family_migration` is false.

Inspect `capabilities.runtime_acceptance` and `cli_acceptance` before claiming
tested compatibility. Membership is path-specific VM evidence, not a general
allowlist. An absent runtime is unverified and should trigger a bounded probe
with the actual command when compatibility matters.

Require lifecycle fields appropriate to the workflow:

- `foreground_modes` contains the selected mode;
- `foreground_owned_resources`, `resources_close_when_run_exits`,
  `setup_helper_session_scoped`, and `setup_helper_drops_privileges` are true;
- `concurrent_runs_isolated` is true when running independent policies in
  parallel;
- `descendant_cgroup_lifetime` and `upstream_unreachable_fail_closed` are true
  for long-lived or failure-sensitive commands.

## Run and inspect

```bash
heimdall run --policy <policy> -- curl https://example.com
heimdall logs list --json
heimdall logs query --run RUN_ID --kind flow.close --jsonl
heimdall logs verify --run RUN_ID --json
```

Omit `--policy` to use `proxy.default_policy`. Keep argv after `--`. Heimdall
may re-enter through `systemd-run --user --scope`; the resolved global config
path and argv are preserved. It returns the immediate child's status but keeps
interception alive until every descendant leaves the cgroup.

Read [references/commands.md](references/commands.md) for diagnosis and
[references/events.md](references/events.md) for direct Linux-tool recipes.

## Preserve ownership boundaries

- Do not change host routing, firewall, DNS, or proxy state merely to use
  Heimdall.
- Do not install file capabilities or setuid on the full CLI. Authorize only
  the exact `heimdall __setup-worker` command.
- Do not upload or print capture bytes without explicit authority; they can
  contain credentials and personal data.
- Treat the unprivileged setup helper as part of one run. On unexpected owner
  exit it kills and removes that run's cgroup to prevent direct-egress fallback.
