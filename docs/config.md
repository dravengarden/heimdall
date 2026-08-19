# Configuration

Heimdall reads exactly one `/etc/heimdall/config.<format>` file. TOML, YAML,
and JSON enter the same strict schema. Unknown fields, duplicate named
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
block_max_bytes = 65536
flush_interval_ms = 100
boundaries = ["transport", "tls_plaintext.runtime", "tls_plaintext.relay"]
directions = ["client_to_remote", "remote_to_client"]
redact_env = []

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
config; the foreground session reads the absolute `password_file`, removes one trailing
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
decision. Without `--network`, the command explains TCP.

## Capture and decrypt

The three product layers are ordered and independently explicit. Proxy decides
whether and where a connection is relayed. Capture decides whether bytes are
retained. Decrypt chooses what those retained bytes represent:

```toml
[capture]
mode = "on"
max_bytes_per_flow = 1048576
block_max_bytes = 65536
flush_interval_ms = 100
boundaries = ["tls_plaintext.runtime"]
directions = ["client_to_remote", "remote_to_client"]
redact_env = ["API_TOKEN"]

[decrypt]
mode = "off"
```

TLS decryption has two opt-in modes:

```toml
# Observe supported application TLS APIs without terminating TLS.
[decrypt]
mode = "runtime"
```

```toml
# Terminate and rebuild TLS at the relay, independent of client language.
[decrypt]
mode = "relay"
ca_cert = "/var/lib/heimdall/tls/ca.pem"
ca_key = "/var/lib/heimdall/tls/ca-key.pem"
```

Both modes require `capture.mode = "on"`; otherwise validation returns
`decrypt_requires_capture`. `runtime` currently attaches paired OpenSSL
`SSL_read`, `SSL_read_ex`, `SSL_write`, and `SSL_write_ex` entry/return uprobes
and records only bytes reported as successfully transferred. It requires no
trust change and remains compatible with certificate pinning and mTLS, but
does not claim coverage for Go, rustls, BoringSSL, JVM, or stripped/static TLS
implementations. Each API event is bounded to the byte count reported by
`agent.capabilities.decrypt.runtime_max_bytes_per_event`. Runtime mode is
foreground-owned: its setup helper discovers `libssl` images
already mapped when the run starts, opens one perf ring per online CPU,
transfers those ring FDs and the probe links, drops to the invoking user, and
remains only for the run lifetime to retain Aya's probe state. The foreground
process maps and reads inherited rings. Setup fails if none can be attached. Images
loaded only after exec are not observed in the current alpha. Require
`execution.daemon_required = false` and verify the selected runtime capability.

`relay` detects TLS ClientHello records at the relay, records parsed SNI and
offered ALPN as `tls.client_hello`, verifies the upstream
certificate with the native trust store, mirrors the negotiated ALPN, signs a
per-host leaf certificate, and captures the resulting plaintext. Non-TLS TCP
passes through unchanged. Generate the CA with
`heimdall tls init-ca --dir /var/lib/heimdall/tls --json`, then explicitly trust
`ca.pem` in each wrapped client. The private key must be a regular file with no
group or other permissions and must be readable by the user invoking
`heimdall run`. Certificate pinning and client-certificate mTLS are
intentionally unsupported in this mode.

`capture.mode` is `off` or `on`; event metadata remains available in either
case. `max_bytes_per_flow` defaults to 1 MiB and must be between 1 byte and
64 MiB. The limit is shared by both directions. `boundaries` and `directions`
are payload allowlists; they never suppress lifecycle, policy, DNS, TLS, or
flow metadata. Runtime and relay decrypt modes require their corresponding
`tls_plaintext.*` boundary to be allowed.

`block_max_bytes` defaults to 64 KiB and bounds each published blob to at most
1 MiB. `flush_interval_ms` defaults to 100 ms and must be between 10 and 5000
ms. Per-flow, per-direction buffers flush on size, interval, or close; each
`flow.data.data.block` reports its one-based index and actual flush reason.
The effective block size is also bounded by the remaining per-flow byte limit.

`redact_env` accepts up to 32 portable environment variable names. The secret
values must be present and non-empty in the environment inherited by
`heimdall run`; `heimdall agent` reports `redaction_values_ready=false` and
withholds `actions.execute_prefix` otherwise. Values are matched as exact
bytes across read boundaries and replaced with the same number of `*` bytes
before hashing or blob publication. Names and a value count may appear in
agent/run metadata; values never do. Each value is limited to 4096 bytes and
all values together to 65536 bytes. This is literal redaction, not a parser:
encoded, transformed, or otherwise unlisted secrets remain visible.

When enabled, retained bytes
are stored once below the run's private `blobs/sha256/` tree and referenced by
`flow.data` records. JSONL contains lengths, truncation, boundary, digest, and
relative path—never inline base64. `heimdall logs verify` checks every referenced
blob and the manifest's count/byte summary.

Capture can still contain sensitive application bytes and has no upload path. Use
`heimdall logs prune` for explicit retention. Only a `flow.data.data.boundary`
of `tls_plaintext.runtime` or `tls_plaintext.relay` proves plaintext; never
infer it from a port, file name, SNI, or byte shape.

## Machine-readable validation

```bash
heimdall config validate --json
```

Success:

```json
{"contract":"heimdall.config.validate/v2","valid":true,"path":"/etc/heimdall/config.toml","diagnostics":[]}
```

Semantic failures are returned together with stable codes and repair hints:

```json
{
  "contract": "heimdall.config.validate/v2",
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

Generate a canonical starter with `heimdall init --format toml|yaml|json`.
Existing files are preserved unless `--force` is
explicit.
