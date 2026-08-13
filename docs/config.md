# Configuration

Heimdall reads exactly one `/etc/heimdall/config.<format>` file. Supported
formats are TOML, YAML (`.yaml` or `.yml`), JSON, and Nickel (`.ncl`). The
extension selects the parser; all four decode into the same Rust schema and run
the same semantic validation.

```toml
[proxies.default]
type = "socks5"
addr = "127.0.0.1:1080"

[run]
proxy = "default"
dns = "fake"
```

`proxies` is a map of names to SOCKS5 endpoints. `run.proxy` chooses the
default; `heimdall run --proxy NAME` overrides it for one invocation.

For username/password authentication, add an `auth` table with `username` and
`passwordFile`. The password file is read by the daemon and should be owned by
root with restrictive permissions.

`run.dns` accepts `fake` or `system`. Fake mode preserves the hostname until
the SOCKS5 CONNECT request, allowing the upstream to resolve private names.
System mode leaves resolution to the host.

Daemon listener and fake-IP pool defaults are intentionally omitted from the
starter file. They may be overridden under `daemon`.

## Strict validation

`heimdall config validate` rejects:

- unsupported extensions or ambiguous automatic discovery;
- syntax errors, unknown fields, wrong types, and unknown connection types;
- an undeclared `run.proxy` or an invalid proxy name/address;
- empty authentication usernames or relative `passwordFile` paths;
- malformed, zero-port, or colliding daemon listener addresses;
- cgroup paths outside `/sys/fs/cgroup`;
- non-canonical or wrong-family fake-IP CIDRs;
- Nickel evaluation failures or exported values that fail the same schema.

Use `heimdall config validate --json` for a stable agent/CI result. Nickel is
evaluated with `nickel export --format json`; the packaged Nix executable puts
Nickel on its private `PATH`.

Generate a minimal starter without changing the schema:

```bash
heimdall init --format toml
heimdall init --format yaml
heimdall init --format json
heimdall init --format nickel
```

Existing configs are preserved unless `--force` is explicit. Run `heimdall
config show` to inspect the selected source and validate it before restarting
the daemon.
