---
name: heimdall
description: Operate and configure the Heimdall proxychains-style CLI wrapper. Use when an agent needs to run a command through a named egress policy, create or strictly repair Heimdall TOML/YAML/JSON configuration, inspect daemon health, diagnose command-scoped SOCKS5 routing or fake/system DNS, or work with heimdall.service and /etc/heimdall/config.*.
---

# Heimdall

Treat Heimdall as a command wrapper, not a host-wide traffic router. It affects
only cgroups registered by `heimdall run`.

## Start with the machine contract

Run:

```bash
heimdall agent
```

Parse the single `heimdall.agent/v4` JSON object. Exit 0 means ready, exit 1
means the document explains why, and exit 2 is invalid CLI usage. Read stable
error `code` values before messages. Execute `actions` as argv arrays; never
join or evaluate them as shell text.

Require `daemon.health.contract` to be `heimdall.daemon.health/v2`,
`daemon.health.ready` to be true, `daemon.health.relay_port` to be positive,
and `daemon.health.decrypt_mode` to match `config.decrypt.mode`. Treat
`daemon_unreachable`, `daemon_contract_mismatch`,
`daemon_not_ready`, and `daemon_config_mismatch` as hard stops before executing
a wrapped command.

Use `heimdall help -v` only when deeper command discovery is needed.

The daemonless redesign and agent-first JSONL contracts are documented in
[references/events.md](references/events.md). Phase 1 `heimdall logs` commands
are available for run lifecycle and TCP/UDP metadata. Inspect
`capabilities.logs.flow_events` before expecting UDP, payload, TLS, or derived
HTTP records; continue using current capture files for unsupported evidence.

If capture is requested, inspect `config.capture`, `config.decrypt`,
`capabilities.capture`, and `capabilities.decrypt`. Require capture `mode: on`
and a suitable byte limit before either decrypt mode. Read each capture open
record's `payload`; only `tls_plaintext` is decrypted.

Choose `runtime` only when `runtime_libraries` contains the client's TLS
implementation and account for `runtime_discovery`; a newly
introduced OpenSSL image requires a daemon restart before wrapping the command.
Also require `daemon.health.runtime.attached_images` to be greater than
zero and use `runtime_apis` plus `runtime_max_bytes_per_event` as the
capture boundary. It changes no trust and supports pinning/mTLS, but absence
from the library or API arrays means no plaintext guarantee. Choose `relay`
for TLS-library-independent capture only with explicit authority to install local trust. If
`ca_material_ready` is false, execute `actions.tls_ca_init` as an argv array,
then trust its public `ca_cert`; never expose or copy `ca_key`. Do not select
relay mode for certificate-pinned or client-certificate mTLS traffic.

## Validate and repair configuration

Read [references/config.md](references/config.md) before creating or changing a
config. Keep exactly one discovered
`/etc/heimdall/config.{toml,yaml,yml,json}` file unless `--config` is
explicit.

After every edit, run:

```bash
heimdall config validate --json
```

If validation fails, process every `diagnostics` entry. Use `code` for control
flow, `path` to locate the field, and `hint` as the repair constraint. Repeat
until `valid` is true. An `outbound_network_mismatch` must be repaired by
enabling the required protocol on that outbound or selecting a capable
outbound; never silently change `route` to `direct`. Never put a password value
in config; use an absolute `password_file`.

Then run:

```bash
heimdall config explain --policy <policy> --domain example.com --port 443 --json
heimdall config explain --policy <policy> --network udp --domain example.com --port 443 --json
heimdall agent --policy <policy>
```

Use `config explain` to verify ordered rule selection before execution. Do not
treat configuration validity or an explained decision as daemon or network
acceptance.

Before choosing a UDP workload, inspect `capabilities.udp` in the agent report.
Bidirectional, multi-response sessions are supported for connected sockets.
IPv4 also supports connectionless multi-target traffic and concurrent sockets
sharing one source port. The aggregate booleans stay false because IPv6 does
not support those cases; inspect the `*_ipv4` and `*_ipv6` fields rather than
guessing. `connectionless_ipv6_single_peer` permits one peer per IPv6 socket,
and `ipv4_mapped_ipv6_socket` covers dual-stack clients targeting IPv4. Respect
`max_socks5_payload_bytes`. `quic_ipv4` and `quic_ipv6` permit single-path
HTTP/3 on either family; do not infer address-family migration while
`quic_address_family_migration` is false.

Before claiming compatibility for a language runtime, inspect
`capabilities.runtime_acceptance`. Treat each array as protocol-specific VM
evidence, not as a general allowlist. An absent runtime means unverified and
should trigger a bounded probe with the actual command when compatibility is
required.

Inspect `capabilities.cli_acceptance` for protocol-specific CLI evidence and
`capabilities.lifecycle` before executing a long-lived or failure-sensitive
workflow. Descendants remain inside the command policy after their immediate
parent exits. Do not add environment proxy variables or a direct fallback for
them. `daemon_restart_enforcement_continuity` means registered traffic remains
intercepted and fails closed while a restarted daemon is unavailable. Refuse a
workflow that requires existing connections to survive while
`daemon_restart_continuity` or `daemon_restart_existing_connections` is false.
Policy and fake-DNS recovery fields mean the userspace decision is restored
after daemon readiness.
`pinned_state_schema` must match the installed binary.
`transactional_program_upgrade` means a partial link replacement is rolled
back before startup fails.

## Run a command

```bash
heimdall run --policy <policy> -- curl https://example.com
```

Omit `--policy` to use `proxy.default_policy`. DNS belongs to the policy and is
not a per-run override. Keep the wrapped command after `--`. Read
[references/commands.md](references/commands.md) for runtime diagnostics.

## Preserve the ownership boundary

- Do not change host routing, firewall, DNS, or proxy state merely to use
  Heimdall.
- Do not start the privileged daemon when the user asked only for config review.
- For runtime failures, collect `heimdall agent`, `heimdall status --json`, and
  recent `heimdall.service` logs before changing state.
- Do not claim runtime TLS coverage beyond
  `capabilities.decrypt.runtime_libraries` and `runtime_apis`.
- Do not enable capture without explicit retention intent; its root-only files
  can contain credentials and other application data. Heimdall does not rotate
  them.
- Never delete `/sys/fs/bpf/heimdall` manually. For an explicitly requested
  uninstall or incompatible-schema repair, stop the service, prove all wrapped
  workloads exited, then run `heimdall ebpf cleanup --json`. Treat
  `daemon_active` and `active_workloads` as hard stops; never work around them.
