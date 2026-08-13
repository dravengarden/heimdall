# Configuration

Heimdall reads exactly one `/etc/heimdall/config.<format>` file. TOML, YAML,
JSON, and Nickel enter the same strict schema. Unknown fields, duplicate named
objects, invalid enums, bad references, unsupported protocol capabilities, and
contradictory DNS/routing choices are rejected before a command is started.

## Minimal configuration

```toml
version = 1

[proxy]
default_policy = "default"

[proxy.outbounds.default]
type = "socks5"
server = "127.0.0.1"
server_port = 1080
network = ["tcp"]

[proxy.policies.default.dns]
mode = "fake"

[proxy.policies.default.final]
tcp = { type = "route", outbound = "default" }
udp = { type = "reject", method = "refused" }

[capture]
mode = "off"

[decrypt]
mode = "off"
```

`proxy.outbounds` describes how traffic leaves. `proxy.policies` describes the
ordered decision for one `heimdall run` invocation. The CLI uses
`proxy.default_policy` unless `--policy` is present.

## Outbounds

The data plane supports SOCKS5 TCP CONNECT and UDP ASSOCIATE:

```toml
[proxy.outbounds.corp]
type = "socks5"
server = "127.0.0.1"
server_port = 1081
network = ["tcp", "udp"]
connect_timeout = "10s"

[proxy.outbounds.corp.auth]
username = "alice"
password_file = "/etc/heimdall/secrets/corp-password"
```

`server` is a hostname, IPv4 address, or unbracketed IPv6 address. Durations
accept positive integer `ms`, `s`, or `m` values. Passwords never belong in the
config; the daemon reads the absolute `password_file`, removes one trailing
newline, and enforces the SOCKS5 1–255 byte limit.

`network` is a strict capability declaration. A `route` action is rejected
when its rule or final protocol is absent from the selected outbound. Use
`["tcp"]`, `["udp"]`, or both; Heimdall never silently changes a routed flow to
direct egress.

## Policies and ordered rules

Rules are evaluated in declaration order. The first matching rule wins. Fields
inside one list are OR; different fields are AND.

```toml
[[proxy.policies.default.rules]]
name = "corp-domains"
action = { type = "route", outbound = "corp" }

[proxy.policies.default.rules.match]
network = ["tcp", "udp"]
domain_suffix = ["internal.example.com"]
port = [443]

[[proxy.policies.default.rules]]
name = "local-services"
action = { type = "direct" }

[proxy.policies.default.rules.match]
network = ["tcp"]
ip_cidr = ["127.0.0.0/8", "::1/128"]

[[proxy.policies.default.rules]]
name = "deny-smtp"
action = { type = "reject", method = "refused" }

[proxy.policies.default.rules.match]
network = ["tcp"]
port = [25]
```

Supported match fields are `network`, `domain`, `domain_suffix`, `ip_cidr`,
`port`, and `{ start, end }` entries under `port_range`. Domain and IP matchers
must be separate rules because one connection is classified by either its
fake-DNS domain identity or its literal IP identity.

Every policy must declare terminal TCP and UDP actions:

```toml
[proxy.policies.default.final]
tcp = { type = "route", outbound = "default" }
udp = { type = "reject", method = "refused" }
```

There is no implicit first outbound and no failure fallback to direct.
`route` must name an existing outbound, `direct` is an explicit authorization,
and `reject` fails the connection or datagram.

UDP proxying covers connected datagram sockets on both families and
connectionless IPv4 `sendto`/`sendmsg`. One bidirectional SOCKS5 association
(or direct socket) is reused per connected socket or IPv4 socket-destination
pair, including asynchronous and multiple responses. IPv4 token correlation
supports several destinations from one socket and concurrent sockets sharing a
source port. Fragmented SOCKS5 UDP responses are rejected, and SOCKS5 payloads
are limited to 65,245 bytes so the largest domain header still fits one UDP
datagram. IPv6 connectionless sockets support one peer, including IPv4-mapped
destinations used by dual-stack clients, through family-and-port correlation.
Multiple destinations from one IPv6 socket and simultaneous IPv6 sockets
sharing one explicitly bound source port are rejected because that key becomes
ambiguous. HTTP/3/QUIC over IPv4 and native IPv6 is acceptance-tested for a
stable single path; migration across address families is not declared.

## DNS

`dns.mode = "fake"` redirects UDP and TCP port 53 to Heimdall. A/AAAA answers
carry stable fake IPs so the relay can recover the hostname and send a SOCKS5
domain request. Domain rules therefore require fake DNS.

`dns.mode = "system"` explicitly allows UDP/TCP port 53 to reach the host
resolver. The relay then sees resolved IPs, so domain rules are rejected and
policies must use `ip_cidr`, `port`, or protocol matchers.

Use `heimdall config explain --network udp ... --json` to inspect a UDP policy
decision. `--network` defaults to `tcp` for compatibility.

## Capture and decrypt

The three product layers are represented independently, but only proxy is
enabled in this release:

```toml
[capture]
mode = "off"

[decrypt]
mode = "off"
```

Any other mode is rejected instead of being accepted as a no-op.

## Daemon settings

Most installations can omit this section. The internal relay is intentionally
fixed to IPv4 and IPv6 loopback port 12345 so configuration cannot drift from
the eBPF redirect target.

```toml
[daemon]
dns_port = 5358
api_listen = "127.0.0.1:9999"
```

`api_listen` must be loopback-only. Both DNS transports bind IPv4 and IPv6
loopback on `dns_port`; all listener conflicts are rejected before readiness.

## Machine-readable validation

```bash
heimdall config validate --json
```

Success:

```json
{"contract":"heimdall.config.validate/v1","valid":true,"path":"/etc/heimdall/config.toml","diagnostics":[]}
```

Semantic failures are returned together with stable codes and repair hints:

```json
{
  "contract": "heimdall.config.validate/v1",
  "valid": false,
  "path": "/etc/heimdall/config.toml",
  "diagnostics": [
    {
      "code": "unknown_outbound",
      "path": "$.proxy.policies.default.final.tcp.outbound",
      "message": "outbound `missing` is not declared",
      "hint": "Choose one of: default."
    }
  ]
}
```

Agents should repair every diagnostic, validate again, and then run
`heimdall agent --policy <name>`. Syntax errors may yield one parser diagnostic;
semantic validation aggregates independent errors in one response.

After validation, inspect an ordered TCP decision without executing a command:

```bash
heimdall config explain --policy default --domain example.com --port 443 --json
heimdall config explain --policy default --ip 192.0.2.10 --port 443 --json
```

The `heimdall.config.explain/v1` document identifies the matched rule, or uses
`null` when the policy's final TCP action wins. Domain decisions are meaningful
only for policies using fake DNS; strict validation rejects domain rules under
system DNS.

Generate a canonical starter with `heimdall init --format
toml|yaml|json|nickel`. Existing files are preserved unless `--force` is
explicit.
