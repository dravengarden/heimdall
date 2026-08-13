# Configuration reference

Heimdall accepts `.toml`, `.yaml`/`.yml`, `.json`, and `.ncl`. Keep exactly one
discovered `/etc/heimdall/config.<format>` file. All formats use this model:

```text
version = 1
proxy.default_policy -> proxy.policies.<name>
proxy.outbounds.<name> = SOCKS5 TCP/UDP endpoint
proxy.policies.<name>.dns.mode = fake | system
proxy.policies.<name>.rules[] = ordered match + terminal action
proxy.policies.<name>.final.tcp = route | direct | reject
proxy.policies.<name>.final.udp = route | direct | reject
capture.mode = off
decrypt.mode = off
daemon = optional implementation settings
```

Use `heimdall init --format toml|yaml|json|nickel` for exact syntax. Do not
translate field names between formats.

## Outbound

```yaml
proxy:
  outbounds:
    default:
      type: socks5
      server: 127.0.0.1
      server_port: 1080
      network: [tcp, udp]
      connect_timeout: 10s
```

Optional auth uses `auth.username` and an absolute `auth.password_file`. Never
put the password value in config. `network` declares strict protocol
capabilities; a rule or final action cannot route UDP through a TCP-only
outbound (or TCP through a UDP-only outbound).

## Rule

```yaml
- name: corp-domains
  match:
    network: [tcp, udp]
    domain_suffix: [internal.example.com]
    port: [443]
  action:
    type: route
    outbound: corp
```

Matchers: `network`, `domain`, `domain_suffix`, `ip_cidr`, `port`, and
`port_range` entries with `start` and `end`. The first rule wins. Lists are OR;
different fields are AND. Do not mix domain and IP matchers in one rule.

Actions:

- `route` requires an existing outbound capable of every protocol selected by
  that rule or final action.
- `direct` explicitly authorizes a native connection from the daemon.
- `reject` currently requires `method: refused`.

`final.tcp` and `final.udp` are mandatory. Connected UDP may route through
SOCKS5 UDP ASSOCIATE, connect directly, or reject. One bidirectional association
is reused per connected socket and supports multiple responses. SOCKS5 payloads
must not exceed the `agent.capabilities.udp.max_socks5_payload_bytes` value.
Connectionless IPv4 and concurrent IPv4 sockets sharing one source port are
supported through per-flow tokens. IPv6 supports one peer per connectionless
socket and IPv4-mapped destinations, but not multi-target or same-port
concurrency. Multicast and fragmented SOCKS5 responses are not supported.
`quic: ipv4` covers acceptance-tested HTTP/3 to IPv4 destinations only.

## DNS invariants

- `fake` preserves hostname identity and permits domain rules. UDP and TCP port
  53 are redirected to Heimdall.
- `system` sends port 53 to the host resolver and forbids domain rules because
  the relay sees only resolved IPs.

## Repair protocol

Run `heimdall config validate --json`. Iterate over every `diagnostics` item:

1. Locate the field using `path`.
2. Branch on stable `code`, not message text.
3. Apply `hint` without inventing unsupported values.
4. Validate again until `valid` is true.
5. Explain representative domain/IP decisions with `heimdall config explain`;
   add `--network udp` for UDP (the default is TCP).
6. Run `heimdall agent --policy <name>` before execution.

Use `heimdall config explain --policy NAME --domain HOST --port PORT --json`
or replace `--domain` with `--ip` to verify first-match rule ordering without
executing a command.

Never respond to `outbound_network_mismatch` by weakening UDP to direct.
Never respond to `domain_rule_requires_fake_dns` by keeping a rule that cannot
match; choose fake DNS or rewrite the policy using IP matchers.

Daemon settings are normally omitted. If needed, only set loopback
`api_listen`, `dns_port`, cgroup, and fake-IP pools. The relay itself is fixed
to IPv4/IPv6 loopback port 12345 and cannot be exposed or mismatched by config.
