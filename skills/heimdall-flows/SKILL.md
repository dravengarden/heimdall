---
name: heimdall-flows
description: |
  Query the heimdall flow log to see what k8s pods talked to externally
  (and, once `heimdall run` is past its experimental phase, ad-hoc CLI
  processes too). Triggers on tasks like "did pod X reach hostname Y",
  "what egress is namespace Z making", "show flows for the last hour".
  Wraps `heimdall flows {list,search,show}`. The daemon must be running
  (otherwise: see heimdall-status).
license: MIT
metadata:
  author: dravengarden
  version: '0.1.0'
---

# heimdall flows — query the egress flow log

Use when you need to see *what a pod (or proxied CLI process) connected
to externally* — destination hostname, port, which upstream connection
was picked, byte counts, errors.

The flow log is a sqlite database at `/var/lib/heimdall/flows.db`,
auto-pruned at `runtime.flowRetentionSecs` (default 3 days). The CLI is
a read-only window into it.

## Three subcommands

```bash
heimdall flows list   [OPTIONS]            # most-recent flows, newest first
heimdall flows show   <FLOW_ID>            # single flow by id
heimdall flows search [OPTIONS] [QUERY]    # filter by host/pod/connection
```

Run `heimdall --help` for the complete option matrix (all subcommands +
options dump in one shot — heimdall's `--help` is recursive).

## Common patterns

### "What did pod X talk to in the last hour?"

```bash
heimdall flows search --pod my-pod-7c5d4 --since 1h --json
```

`--since` accepts `Nm`, `Nh`, `Nd`. Default output is a column table;
add `--json` for one-flow-per-line JSON (jq-friendly).

### "Did anything connect to grafana.example.com?"

```bash
heimdall flows search --host grafana.example.com --json
# Or substring match:
heimdall flows search --host-contains conviva
```

### "Which pods used the `conviva` upstream?"

```bash
heimdall flows search --connection conviva --since 24h --json | \
  jq -r '"\(.namespace)/\(.pod_name) -> \(.dst_host // .dst_ip)"' | sort -u
```

### "Inspect one flow in detail (incl. tap messages if observe=true)"

```bash
heimdall flows show 19368
# Includes plaintext messages from the Phase B uprobe tap when
# `observe = true` was in effect for that pod's routing decision.
```

## Output schema (when `--json`)

| Field | Meaning |
|---|---|
| `id` | flow id (use with `flows show`) |
| `socket_cookie` | kernel cookie pinning this connection |
| `cgroup_id` | source cgroup (pod or `heimdall run` cgroup) |
| `pod_uid` / `namespace` / `pod_name` | resolved via PodInformer; null for non-pod cgroups |
| `connection_name` | which named upstream was used. Special values: `bypass` (eBPF skipped relay — synthetic log entry), `default`/`conviva`/`...` (real relay flow) |
| `dst_host` | hostname (when fake-IP DNS round-tripped, ATYP=0x03) |
| `dst_ip` | IPv4 used by the pod's `connect(2)` |
| `dst_port` | port |
| `ts_start_us` / `ts_end_us` | microsecond Unix timestamps |
| `bytes_up` / `bytes_down` | byte counters (closed flows only) |
| `upstream_addr` | resolved SOCKS5 server address |
| `atyp` | `domain` (hostname mode) or `ip` (literal IP) |
| `error` | non-null = relay-side failure (e.g. SOCKS5 auth, DNS, conn refused) |

## Filtering tips for AI agents

- **Skip bypass noise**: most flows are intra-cluster (pod ↔ Service) and
  show `connection_name: "bypass"`. To see real egress traffic only:
  `... | jq 'select(.connection_name != "bypass")'`.
- **External-only**: filter on `dst_host != null` to see what fake-IP DNS
  caught (excludes IP-literal connections).
- **Errors only**: `... | jq 'select(.error != null)'`.

## Live tail (HTTP API)

The CLI is one-shot. For live streaming use the WebSocket at
`ws://127.0.0.1:9999/api/ws/flows` or the JSON REST at
`http://127.0.0.1:9999/api/flows?limit=...`. Both ship the same schema.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `error opening flow store` | daemon not running, or `state_dir` wrong | `systemctl status heimdall` — see heimdall-status skill |
| empty results despite traffic | route was `use: system` (eBPF bypass) — no flow is recorded | check the routing decision in heimdall.ncl |
| `dst_host` always null | pod connected by IP literal, never went through fake-IP DNS | check CoreDNS forward target on the cluster |

## Related skills

- `heimdall-status` — verify daemon is up before querying
- `heimdall-config` — edit routing rules so a pod's flows actually appear
