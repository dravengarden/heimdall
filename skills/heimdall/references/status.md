# `heimdall status` — daemon health snapshot

First step when:
- A pod's external connection isn't behaving as expected
- You're not sure if heimdall is running, or which config it loaded
- You need a quick "everything OK?" check before deeper investigation

## Command

```bash
heimdall status            # human-readable two-column view
heimdall status --json     # one-line JSON for AI agents / scripts
```

Reads the config the daemon is using and prints a small summary plus
a probe of the relay listener.

## Output (default)

```
config         /etc/heimdall/heimdall.ncl
connections    3
pod rules      3
default use    default
default observe false
relay listen   0.0.0.0:12345
dns listen     0.0.0.0:5358
fake-IP CIDR   198.19.0.0/16
state dir      /var/lib/heimdall
retention      259200s
flows in store 1234
relay         ok (port reachable)
```

## Output (`--json`)

```json
{
  "config": "/etc/heimdall/heimdall.ncl",
  "connections": 3,
  "pod_rules": 3,
  "default_use": "default",
  "default_observe": false,
  "relay_listen": "0.0.0.0:12345",
  "dns_listen": "0.0.0.0:5358",
  "fake_ip_cidr": "198.19.0.0/16",
  "state_dir": "/var/lib/heimdall",
  "flow_retention_secs": 259200,
  "flows_in_store": 1234,
  "relay_reachable": true
}
```

`flows_in_store` is `null` when the sqlite file is missing or
unreadable; `relay_reachable` is `false` when the relay port refuses
TCP. Both are independent of the daemon's HTTP API state.

| Field | Meaning |
|---|---|
| `config` | which file the daemon loaded |
| `connections` | count of named upstreams in `connections:` |
| `pod_rules` | count of `podRouting.rules` entries |
| `default_use` / `default_observe` | the catchall decision |
| `relay_listen` / `dns_listen` | eBPF redirect target + fake-IP DNS port |
| `flows_in_store` | row count in `flows.db` (use `flows.md` for content) |
| `relay_reachable` | `true` if the listen port accepts a TCP connection |

## Richer state via the HTTP API

`heimdall status` is the CLI snapshot. For everything else (per-tap
attached count, informer health, `default_egress_policy`, recent
attach failures, panics) hit the API:

```bash
curl -s 127.0.0.1:9999/api/status | jq '.tap, .informer, .default_egress_policy'
```

Notable JSON fields the CLI doesn't surface:

```jsonc
{
  "default_egress_policy": "redirect",          // or "bypass"
  "informer": {
    "synced": true,
    "pod_count": 38,
    "last_event_secs_ago": 18                   // > 60 = stalled
  },
  "tap": {
    "attached": 48,
    "scanners": { "libssl": 10, "go": 35, "rustls": 2, "boringssl_static": 1 },
    "recent_failures": [
      { "scanner": "rustls", "path": "...", "error": "...", "ts_us": ... }
    ],
    "rescan": { "enabled": true, "period_secs": 30, "ticks": 412, "panics": 0 }
  }
}
```

`tap.rescan.panics > 0` is always a bug. `informer.last_event_secs_ago
> period_secs * 2` indicates a stalled apiserver connection.

## Failure interpretation

| Output | Diagnosis | Next step |
|---|---|---|
| `relay_reachable: false` (or `relay DOWN`) | daemon not running OR not bound | `systemctl status heimdall` then `journalctl -u heimdall -n 50` (→ `serve.md`) |
| `flows_in_store: null` and store path exists | sqlite store unhealthy / locked | check `state_dir` perms, disk space, schema version |
| `connections: 0` | config didn't parse, or empty | reload daemon, check journal for parse errors |
| Command itself fails to run | binary missing or wrong PATH | `which heimdall` |

## Read-only

Does not write to the config, database, or BPF maps. Safe to invoke
from CI / cron / status dashboards.

## When NOT to use

- **Streaming health**: `status` is a snapshot. Use the WebSocket at
  `ws://127.0.0.1:9999/api/ws/flows` for live monitoring.
- **Daemon control**: `status` doesn't restart, reload, or modify
  state. Use `systemctl restart heimdall` directly.
