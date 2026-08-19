# Configuration reference

Heimdall accepts `.toml`, `.yaml`/`.yml`, and `.json`. Keep exactly one
discovered `/etc/heimdall/config.<format>` file. All formats use this model:

```text
version = 1
proxy.default_policy -> proxy.policies.<name>
proxy.outbounds.<name> = SOCKS5 TCP/UDP endpoint
proxy.policies.<name>.dns.mode = fake | system
proxy.policies.<name>.rules[] = ordered match + terminal action
proxy.policies.<name>.final.tcp = route | direct | reject
proxy.policies.<name>.final.udp = route | direct | reject
capture.mode = off | on
capture.max_bytes_per_flow = 1..67108864 (default 1048576)
capture.block_max_bytes = 1..1048576 (default 65536)
capture.flush_interval_ms = 10..5000 (default 100)
capture.boundaries[] = transport | tls_plaintext.runtime | tls_plaintext.relay
capture.directions[] = client_to_remote | remote_to_client
capture.redact_env[] = portable environment variable name (maximum 32)
decrypt.mode = off | runtime | relay
decrypt.ca_cert = absolute PEM path (relay only)
decrypt.ca_key = absolute protected PEM path (relay only)
```

Use `heimdall init --format toml|yaml|json` for exact syntax. Do not
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
- `direct` explicitly authorizes a native connection from the session relay.
- `reject` currently requires `method: refused`.

`final.tcp` and `final.udp` are mandatory. Connected UDP may route through
SOCKS5 UDP ASSOCIATE, connect directly, or reject. One bidirectional association
is reused per connected socket and supports multiple responses. SOCKS5 payloads
must not exceed the `agent.capabilities.udp.max_socks5_payload_bytes` value.
Connectionless IPv4 and concurrent IPv4 sockets sharing one source port are
supported through per-flow tokens. IPv6 supports one peer per connectionless
socket and IPv4-mapped destinations, but not multi-target or same-port
concurrency. Multicast and fragmented SOCKS5 responses are not supported.
Ambiguous IPv6 multi-target sends and duplicate explicit source-port binds are
rejected. `quic_ipv4` and `quic_ipv6` cover acceptance-tested single-path
HTTP/3; address-family migration remains false.

Configuration validity does not prove a particular language runtime. After
validation, compare the intended path with `capabilities.runtime_acceptance`;
probe the actual command when its runtime is absent from that path's array.

## Capture and decrypt boundary

Enable capture only when the user intends to retain traffic. It writes private,
content-addressed blobs below the run directory and references them from
`heimdall.event/v1` JSONL. The byte limit is shared across both directions.
Blocks are coalesced per flow/direction, bounded by `block_max_bytes`, and
flushed on size, `flush_interval_ms`, or close. Read
`flow.data.data.block.flush_reason`; do not infer timing from file order.
Treat `boundaries` and `directions` as payload allowlists; metadata remains
available for excluded paths. Before execution, require
`agent.config.capture.redaction_values_ready = true`. `redact_env` names exact
secret values supplied through the inherited environment; Heimdall masks them
across observed read boundaries before hashing or blob publication. It does not
redact encoded or transformed variants unless their exact value is also named.
With decrypt off, payload is opaque transport. Runtime
mode is CA-free but currently covers only the TLS libraries listed by
`agent.capabilities.decrypt.runtime_libraries`. Relay mode is TLS-library-independent
but requires client trust and does not support pinning or client-certificate
mTLS. `runtime_discovery` reports when OpenSSL images are scanned: the current
boundary is images already loaded when the run starts. Require
`execution.daemon_required = false` and a positive attached-image result before
the workload starts.
`runtime_apis` and `runtime_max_bytes_per_event` define the exact
probe boundary. Both decrypt modes require capture on.

Validate the bounded limit, then inspect the normalized values at
`agent.config.capture`/`agent.config.decrypt` and capability boundary
at `agent.capabilities.capture`/`agent.capabilities.decrypt`. Use
`heimdall tls init-ca --json` only after explicit relay trust authority. Never
weaken file permissions or expose `ca_key`; it must remain readable by the same
user that invokes relay mode. Heimdall never uploads captures; use
`heimdall logs prune` for explicit retention.

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

Foreground relay and DNS ports plus fake-IP pools are internal per-run state.
They cannot be exposed or selected by config.
