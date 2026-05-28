# `heimdall serve` — the daemon (read-only reference)

> **Don't run this manually.** The daemon attaches eBPF programs to
> a cgroup, opens privileged listeners, and writes a sqlite store.
> Race against the systemd-managed instance = both fail. This file
> is here so an agent can reason about what `serve` does, not so it
> can launch a second copy.

## Invoke through systemd

```bash
sudo systemctl restart heimdall      # apply a config change
sudo systemctl status  heimdall      # one-line health
sudo journalctl  -u    heimdall -f   # live logs
```

For a concise health snapshot use `status.md` instead.

## What `serve` does at startup

```
1. Resolve config path: --config, $HEIMDALL_CONFIG, or auto-discover
   /etc/heimdall/heimdall.{ncl,toml,json,yaml} in that order.
2. Parse + validate (apiVersion, kind, connections, routing).
3. Resolve every connection (read auth.passwordFile when present).
4. Open the flow store at runtime.stateDir/flows.db.
5. Init UnitResolver: scan /sys/fs/cgroup once, build the
   cgroup_id → (unit, slice) map. No external API call — identity
   is read straight off the cgroup hierarchy.
6. Bind fake-IP DNS (UDP runtime.dnsListen).
7. Bind HTTP API (TCP runtime.apiListen) — REST + WebSocket.
8. Bind relay (TCP runtime.listen).
9. Reconcile policy: write CGROUP_POLICY map for every known cgroup
   based on the routing rules.
10. Attach eBPF connect4/connect6 + skb_egress to runtime.cgroup
    (default /sys/fs/cgroup/system.slice) and to /sys/fs/cgroup/user.slice
    for heimdall run.
11. Start tap (Phase B uprobes) if runtime.tap.enabled.
12. sd_notify(READY=1) — systemd marks the unit "active (running)".
13. Spawn watchdog heartbeat (sd_notify WATCHDOG=1 every ~3.3 s
    to satisfy WatchdogSec=10s).
```

A successful startup ends with `INFO heimdall: heimdall ready
listen=0.0.0.0:12345`.

## Flags

`--config <PATH>` is *global* (every subcommand accepts it). When
unset, the daemon auto-discovers the config. `heimdall help serve -v`
lists any additional flags.

## Notable log lines

| Line | Meaning |
|---|---|
| `config loaded path=... connections=N rules=M` | Parse OK |
| `all connections resolved connections=N` | Auth files read OK |
| `flow store ready path=...` | sqlite open + migrations done |
| `unit resolver ready cgroups=K` | UnitResolver finished its initial scan |
| `eBPF connect4 attached cgroup=...` | redirect hook live |
| `eBPF skb_egress attached cgroup=...` | egress hook live |
| `default egress policy written to BPF map policy=Redirect value_bits=0x06` | DEFAULT_POLICY_MAP populated |
| `policy: reconciled writes=N deletes=0 cgroups=K` | per-cgroup policy bytes pushed to BPF |
| `tap: started (Phase B) attached_libs=N` | uprobe tap attached |
| `tap: rescan loop started period_secs=30` | live re-scan ticking |
| `heimdall ready listen=...` | startup gate satisfied |
| `systemd watchdog heartbeat starting period_secs=3.33` | sd_notify watchdog active |
| `tunnel established unit=... connection=... dst=... via=...` | per-flow info-level log |
| `relay: SNI fallback promoted IP-literal connection to hostname` | SNI fallback recovered hostname for an unmapped fake IP |
| `relay error ...` | per-flow failure (SOCKS5 auth, conn refused, etc.) |
| `tap: rescan tick panicked; loop continuing` | rescan caught a panic — bug, but loop continues |

## Diagnosing common startup failures

| Journal line | Cause |
|---|---|
| `connections registry: 'system' is reserved` | Don't declare `connections.system`; use `use: "system"` in a rule |
| `unknown use 'foo' in routing rule` | Misspelled or removed connection name |
| `cannot read passwordFile: ...` | Missing or wrong-perms `secrets/<name>.pw` |
| `failed to attach connect4` | Cgroup doesn't exist or insufficient capabilities |
| `unit resolver: /sys/fs/cgroup not a cgroup v2 mount` | Host is on legacy cgroup v1 or unified hierarchy isn't mounted at the expected path |

## Required capabilities (in the systemd unit)

- `CAP_BPF` — load + attach eBPF programs
- `CAP_NET_ADMIN` — manage network resources
- `CAP_SYS_ADMIN` — bpf() syscalls in some kernels
- `CAP_SYS_PTRACE` — readlink `/proc/<pid>/exe` for the tap's
  Go-binary scanner (across UIDs)
- `CAP_DAC_OVERRIDE` — orphan-cgroup GC needs to rmdir
  user-owned cgroups created by `heimdall run`

## systemd unit hardening (current state)

```
Type            = notify
NotifyAccess    = main
RestartSec      = 1
StartLimitIntervalSec = 60       # in [Unit], not [Service]
StartLimitBurst       = 10
WatchdogSec     = 10s
```

Combined: daemon crash → restart in ~1 s; daemon hang (no
WATCHDOG=1 in 10 s) → SIGKILL + restart; ≥10 crashes in 60 s →
systemd gives up.
