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

Parse the single `heimdall.agent/v8` JSON object. Exit 0 means ready, exit 1
means the document explains why, and exit 2 is invalid CLI usage. Read stable
error `code` values before messages. Execute `actions` as argv arrays; never
join or evaluate them as shell text.

Use `execution` before running a command:

- Require `backend = linux-ebpf-foreground`, `daemon_required = false`,
  `owner = heimdall-run`, and
  `privilege_setup = sudo-then-unprivileged-session-helper` for every decrypt
  mode. Heimdall has no persistent daemon or health endpoint.
- `web_ui_required` must remain false for every executable path.

Use `decision.resolver` before executing a fake-DNS policy:

- `strategy = port53_intercept` needs no user or mount namespace;
- `strategy = private_mount` requires the reported fallback and its runtime
  policy check;
- if `resolver.ready` is false, stop and process `resolver.error.code`; the
  agent deliberately withholds `actions.execute_prefix`;
- execute each `actions.resolver_inspect[]` item as its own argv array. These
  actions are read-only evidence, not permission to change host security.

For relay mode, require `config.decrypt.ca_material_ready = true` before using
`actions.execute_prefix`. If false, branch on
`config.decrypt.ca_material_error.code`; `relay_ca_material_invalid` means the
certificate, key, permissions, signing usage, or key match failed the same
validation used by the runtime.

Use `heimdall help -v` only when deeper command discovery is needed.

## Select evidence boundaries

Read [references/events.md](references/events.md) before consuming run logs.
`heimdall.event/v1` records lifecycle, fake-DNS exchanges, policy decisions,
TCP/UDP and TLS metadata, bounded blob references, and provenance-linked
HTTP/1 header evidence in user-owned JSONL.
Use `heimdall logs schema`, `list`, `path`, `summary`,
`query`, `tail`, `rotate`, `verify`, `recover`, and `prune`; standard `jq`, `rg`, `sed`,
`sort`, `sha256sum`, and `wc` are valid consumers. Do not require or start a
Web UI.
Export all three evidence contracts before writing a parser:
`logs schema --event v1`, `--run v1`, and `--summary v1`.

If capture is requested, inspect `config.capture`, `config.decrypt`,
`capabilities.capture`, and `capabilities.decrypt`. Require capture `mode: on`
and a suitable byte limit, allowed boundary/direction, and
`redaction_values_ready: true` before execution. Treat `redact_env` as exact
byte-value masking, not evidence that encoded or transformed secrets are safe.
Only an explicit
`tls_plaintext.*` boundary is plaintext evidence; never infer it from port,
SNI, process, or byte shape.

Treat `http.request` and `http.response` as optional derived evidence, not
protocol classification. Require `data.parser`, follow every `data.source_seq`
back to `flow.data` with a `tls_plaintext.*` boundary, and expect only the first
complete HTTP/1 header per direction. Common credential headers are fixed-mask
redacted and `body` is always null.

Choose `relay` only with authority to install local trust. Require
`ca_material_ready`, trust only the public `ca_cert`, keep `ca_key` mode 0600
and readable only by the invoking user, and reject pinned or client-certificate
mTLS workflows. Compare `tls init-ca` `ca_cert_sha256` with
`agent.config.decrypt.ca_cert_sha256` before granting command-scoped trust.
If `ca_material_error` reports `relay_ca_material_invalid`, generate replacement
material in a new private directory, update command-scoped client trust, and
then update both config paths. Never silently overwrite CA material still
trusted by a client.
Branch on relay certificate errors: never repair
`tls_upstream_certificate_invalid` by disabling remote verification; for
`tls_upstream_client_auth_required`, switch to runtime mode or disable
decryption because relay mode cannot forward the client's certificate; for
`tls_downstream_certificate_rejected`, install only the configured public CA
in the explicitly wrapped client when authorized.
Treat `tls_downstream_closed_without_close_notify` as ambiguous until the
wrapped command's stderr and exit status identify a trust failure.

Choose `runtime` only when the client uses a reported OpenSSL API. Read
`runtime_discovery`, `runtime_loader_discovery`,
`runtime_loader_images_can_map_after_exec`, and
`runtime_privileged_dynamic_attachment` together. The setup helper pre-attaches
active and system-loader images, then drops privilege before the workload
starts. A loader-known image may map after exec. It changes no trust and can
coexist with pinning/mTLS, but private images outside those paths and
unsupported libraries or APIs have no plaintext guarantee.

## Validate and repair configuration

Read [references/config.md](references/config.md) before creating or changing a
config. Keep exactly one discovered
`/etc/heimdall/config.{toml,yaml,yml,json}` unless global `--config` is
explicit.
Use `heimdall config schema --version v1` for the offline structural contract
and `heimdall config example --format <toml|yaml|json>` for a complete starter.
Still run `heimdall config validate --json`; schema validation cannot resolve
named policies/outbounds or prove runtime capabilities.

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
heimdall logs summary --run RUN_ID --json
heimdall logs query --run RUN_ID --kind flow.close --jsonl
heimdall logs verify --run RUN_ID --json
heimdall logs recover --run RUN_ID --json
```

Omit `--policy` to use `proxy.default_policy`. Keep argv after `--`. Heimdall
may re-enter through `systemd-run --user --scope`; the resolved global config
path and argv are preserved. It returns the immediate child's status but keeps
interception alive until every descendant leaves the cgroup.

For fake DNS, never relax a host-wide user-namespace or AppArmor setting. Read
`decision.resolver.strategy`, `reason`, `private_mount_status`, and `error`
before running. A plain `hosts: files dns` NSS path is redirected at port 53
without a namespace. For `fake_dns_user_namespace_disabled`, use system DNS
when domain identity is unnecessary or move the workload to a compatible host.
For `apparmor_policy_check`, authorize `userns,` only for the exact installed
Heimdall path through a scoped profile when the user permits that host change.

Read the `heimdall.logs.summary/v1` document before scanning payload evidence.
Use its missing/out-of-order sequence counts, active flows, failure codes,
capture truncation, and protocol counters to choose a bounded query. Summary
is operational aggregation; require `logs verify` before making an integrity
claim.

Read [references/commands.md](references/commands.md) for diagnosis and
[references/events.md](references/events.md) for direct Linux-tool recipes.

## Preserve ownership boundaries

- Do not change host routing, firewall, DNS, or proxy state merely to use
  Heimdall.
- Do not install file capabilities or setuid on the full CLI. Authorize only
  the exact `heimdall __setup-worker` command.
- Do not upload or print capture bytes without explicit authority; they can
  contain credentials and personal data.
- Confirm the selected payload boundary and direction are allowlisted. Never
  infer that environment-backed literal redaction covers encodings or derived
  credentials.
- Treat the unprivileged setup helper as part of one run. On unexpected owner
  exit it kills and removes that run's cgroup to prevent direct-egress fallback.
