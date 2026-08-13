# Command workflows

## Inspect without mutation

```bash
heimdall agent
heimdall config path
heimdall config show
heimdall config validate --json
heimdall config explain --policy default --domain example.com --port 443 --json
heimdall config explain --policy default --network udp --domain example.com --port 443 --json
heimdall status --json
```

`agent` is the primary machine contract: one versioned JSON object, stable
error categories, and next actions represented as argv arrays. Exit 0 means
ready, 1 means not ready, and 2 means CLI usage error. It never mutates state.

`config show` prints source text, not a normalized form. `config validate`
evaluates Nickel when applicable, decodes the selected syntax, rejects unknown
fields and types, then runs semantic validation.

`config explain` evaluates one TCP or UDP destination against the selected
policy and returns the first matching rule plus its structured action. TCP is
the default; add `--network udp` for UDP. Use `--ip` instead of `--domain` for
IP/CIDR rules; omit both to test port-only and final actions.

## Run through a proxy

```bash
heimdall agent
heimdall run -- curl https://example.com
heimdall agent --policy corp
heimdall run --policy corp -- curl https://internal.example.com
```

The selected policy owns DNS, ordered rules, and final TCP/UDP actions. The
wrapped process may be re-executed through `systemd-run --user --scope` to
obtain an isolated cgroup.

Inspect `agent.capabilities.udp` before wrapping a UDP command. Connected,
bidirectional multi-response traffic reuses one association per socket.
IPv4 connectionless traffic and concurrent same-source-port sockets are
supported. The aggregate booleans remain false because those IPv6 cases are
unsupported, so branch on `connectionless_ipv4`/`connectionless_ipv6` and the
matching `concurrent_shared_source_port_*` fields. One-peer IPv6 and
IPv4-mapped dual-stack clients have separate positive fields. Do not exceed
`max_socks5_payload_bytes`; `quic_ipv4` and `quic_ipv6` authorize single-path
HTTP/3 on either family. Require `quic_address_family_migration` for workflows
that migrate an existing QUIC connection across families.

Inspect `capabilities.runtime_acceptance` before asserting that a language
runtime is covered. Membership is path-specific (`tcp_fake_dns`, `udp_ipv4`,
or `udp_ipv6`). Absence means no committed VM evidence for that path, not a
configuration error and not proof of incompatibility.

## Diagnose failures

1. Run `heimdall agent` and preserve its JSON even when it exits 1.
2. Follow its `actions.validate` or `actions.status` argv array.
3. If the daemon is unavailable, inspect recent logs:

   ```bash
   journalctl -u heimdall --since "10 min ago" --no-pager
   ```

4. Preview a destination with `heimdall config explain --policy NAME ... --json`.
5. Preview daemon readiness with `heimdall agent --policy NAME`.
6. Reproduce with a small command such as `curl`, preserving the same policy.

Do not equate config validity with connectivity. A real acceptance check must
exercise the selected policy through `heimdall run`.
