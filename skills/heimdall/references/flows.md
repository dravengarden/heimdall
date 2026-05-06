# `heimdall flows` — query the egress log

Use to see *what a pod (or proxied CLI process) connected to
externally* — destination hostname, port, which upstream
connection was picked, byte counts, errors. Plaintext messages
when the routing decision said `observe = true`.

The flow log is a sqlite database at `/var/lib/heimdall/flows.db`,
auto-pruned at `runtime.flowRetentionSecs` (default 3 days). The
CLI is a read-only window into it.

## Three subcommands

```bash
heimdall flows list   [OPTIONS]            # most-recent flows, newest first
heimdall flows show   <FLOW_ID>            # single flow by id
heimdall flows search [OPTIONS] [QUERY]    # filter by host/pod/connection
```

`heimdall help flows -v` for the full option matrix.

## Common patterns

### "What did pod X talk to in the last hour?"

```bash
heimdall flows search --pod my-pod-7c5d4 --since 1h --json
```

`--since` accepts `Nm`, `Nh`, `Nd`. Default output is a column
table; `--json` is one-flow-per-line (jq-friendly).

### "Did anything connect to grafana.example.com?"

```bash
heimdall flows search --host grafana.example.com --json
# Or substring match:
heimdall flows search --host-contains corp
```

### "Which pods used the `corp` upstream?"

```bash
heimdall flows search --connection corp --since 24h --json | \
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
| `connection_name` | the upstream used; special values: `bypass` (eBPF skipped relay), `default` / `corp` / ... (real relay flow) |
| `dst_host` | hostname (when fake-IP DNS round-tripped, ATYP=0x03) |
| `dst_ip` | IPv4/IPv6 used by the pod's `connect(2)` |
| `dst_port` | port |
| `ts_start_us` / `ts_end_us` | microsecond Unix timestamps |
| `bytes_up` / `bytes_down` | byte counters (closed flows only) |
| `upstream_addr` | resolved SOCKS5 server address |
| `atyp` | `domain` (fake-IP DNS hit), `sni` (SNI fallback recovered hostname for IP-literal connection), `ip` / `ip6` (no hostname) |
| `error` | non-null = relay-side failure (SOCKS5 auth, conn refused, ...) |

### Per-flow tap signal (read this triple together)

The `(atyp, dst_host, messages-count)` triple tells AI consumers
whether plaintext capture is expected:

| `atyp` | `dst_host` | What it means |
|---|---|---|
| `domain` | non-NULL, fake-IP from heimdall pool | Fake-IP DNS hit; pod connected by hostname. Plaintext **likely** captured if the binary has tap support. |
| `sni` | non-NULL, original IP in `dst_ip` | **SNI fallback fired AND was used for routing.** Pod connected by IP literal (or stale fake IP); ClientHello carried `server_name`; relay promoted the destination to that hostname so the SOCKS5 upstream gets ATYP=0x03. Plaintext capture depends on the binary's tap support; routing succeeds regardless. |
| `ip` / `ip6` | NULL | Pod connected by IP literal **and** sent no SNI (per RFC 6066, browsers / curl / Bun's `fetch()` to an IP all do this). Plaintext almost certainly not captured; relay forwards by IP. |

## Filtering tips for AI agents

- **Skip bypass noise**: most flows are intra-cluster (pod ↔
  Service) and show `connection_name: "bypass"`. To see real egress
  traffic only:
  `... | jq 'select(.connection_name != "bypass")'`.
- **External-only**: filter on `dst_host != null` to see what
  fake-IP DNS or SNI fallback caught (excludes pure-IP-literal
  connections).
- **Errors only**: `... | jq 'select(.error != null)'`.

## Live tail (HTTP API)

The CLI is one-shot. For live streaming use the WebSocket at
`ws://127.0.0.1:9999/api/ws/flows` or the JSON REST at
`http://127.0.0.1:9999/api/flows?limit=...`. Both ship the same
schema.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `error opening flow store` | daemon not running, or `state_dir` wrong | see `status.md` |
| empty results despite traffic | route was `use: system` (eBPF bypass) — no flow recorded | check the routing decision in `heimdall.<ext>` (see `config.md`) |
| `dst_host` always null and `atyp` is `ip` | pod connected by IP literal, no SNI | check CoreDNS forward target, or accept this as the honest L4-only state |
