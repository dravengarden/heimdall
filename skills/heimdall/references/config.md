# Configuration reference

Heimdall accepts `.toml`, `.yaml`, `.yml`, `.json`, and `.ncl`. The filename
extension selects the parser. Automatic discovery checks for exactly one
`/etc/heimdall/config.<format>` file and rejects ambiguity.

## Minimal schema

```text
proxies.<name>
  type = "socks5"                  required
  addr = "host:port"               required
  description                      optional
  auth.username                    1–255 bytes, optional with auth
  auth.passwordFile                absolute path; content 1–255 bytes

run
  proxy = "default"                optional default
  dns = "fake" | "system"         optional default: fake

daemon                             entirely optional
  cgroup = "/sys/fs/cgroup/system.slice"
  listen = "127.0.0.1:12345"
  relayIp = "127.0.0.1"
  relayIp6 = "::1"
  dnsListen = "127.0.0.1:5358"
  fakeIpCidr = "198.19.0.0/16"
  fakeIp6Cidr = "fc00:198:19::/96"
  apiListen = "127.0.0.1:9999"
```

Proxy names may contain ASCII letters, digits, `.`, `_`, and `-`. `run.proxy`
must name a declared proxy. Listener sockets must be valid, nonzero, and
distinct. Fake-IP CIDRs must be canonical network addresses of the stated IP
family. The daemon removes one trailing newline from `auth.passwordFile` and
rejects an empty or over-255-byte result.

## Minimal examples

TOML:

```toml
[proxies.default]
type = "socks5"
addr = "127.0.0.1:1080"

[run]
proxy = "default"
dns = "fake"
```

YAML:

```yaml
proxies:
  default:
    type: socks5
    addr: 127.0.0.1:1080
run:
  proxy: default
  dns: fake
```

JSON:

```json
{
  "proxies": {
    "default": { "type": "socks5", "addr": "127.0.0.1:1080" }
  },
  "run": { "proxy": "default", "dns": "fake" }
}
```

Nickel:

```nickel
{
  proxies.default = {
    type = "socks5",
    addr = "127.0.0.1:1080",
  },
  run = { proxy = "default", dns = "fake" },
}
```

Generate one with `heimdall init --format toml|yaml|json|nickel`. Existing
files are preserved unless `--force` is supplied. Nickel evaluation requires
the `nickel` executable; the Nix package wraps Heimdall with it on `PATH`.
