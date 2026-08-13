---
name: heimdall
description: Operate and configure the Heimdall proxychains-style CLI wrapper. Use when an agent needs to run a command through a named egress policy, create or strictly repair Heimdall TOML/YAML/JSON/Nickel configuration, inspect daemon health, diagnose command-scoped SOCKS5 routing or fake/system DNS, or work with heimdall.service and /etc/heimdall/config.*.
---

# Heimdall

Treat Heimdall as a command wrapper, not a host-wide traffic router. It affects
only cgroups registered by `heimdall run`.

## Start with the machine contract

Run:

```bash
heimdall agent
```

Parse the single `heimdall.agent/v2` JSON object. Exit 0 means ready, exit 1
means the document explains why, and exit 2 is invalid CLI usage. Read stable
error `code` values before messages. Execute `actions` as argv arrays; never
join or evaluate them as shell text.

Use `heimdall help -v` only when deeper command discovery is needed.

## Validate and repair configuration

Read [references/config.md](references/config.md) before creating or changing a
config. Keep exactly one discovered
`/etc/heimdall/config.{toml,yaml,yml,json,ncl}` file unless `--config` is
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
- Do not infer removed workload, UI, or TLS-observability commands.
