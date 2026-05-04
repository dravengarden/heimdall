---
name: heimdall-serve
description: |
  The heimdall daemon. Normally launched by systemd, NOT invoked
  manually. This skill exists so AI agents understand what the
  daemon does, how it picks up config, and what it logs — useful
  when diagnosing service failures, reading journal output, or
  reasoning about what `serve` is doing without trying to run it.
license: MIT
metadata:
  author: dravengarden
  version: '0.1.0'
---

# heimdall serve — the daemon (read-only skill)

> **Don't run this manually.** The daemon attaches eBPF programs to a
> cgroup, opens privileged listeners, and writes a sqlite store. Race
> against the systemd-managed instance = both fail. This skill is
> here so an agent can reason about what `serve` does, not so it
> can launch a second copy.

## When to invoke (the systemd unit)

```bash
sudo systemctl restart heimdall      # apply a config change
sudo systemctl status  heimdall      # one-line health
sudo journalctl  -u    heimdall -f   # live logs
```

For a concise health snapshot use the `heimdall-status` skill instead.

## What `serve` does at startup

```
1. Resolve config path: --config, $HEIMDALL_CONFIG, or auto-discover
   /etc/heimdall/heimdall.{ncl,toml,json,yaml} in that order.
2. Parse + validate (apiVersion, kind, connections, podRouting).
3. Resolve every connection (read auth.passwordFile when present).
4. Open the flow store at runtime.stateDir/flows.db.
5. Init Kubernetes informer (PodInformer + CgroupResolver) unless
   --no-k8s. If k8s is unreachable, logs a warning and falls back
   to podRouting.default for every cgroup.
6. Bind fake-IP DNS (UDP runtime.dnsListen).
7. Bind HTTP API (TCP runtime.apiListen) — REST + WebSocket.
8. Bind relay (TCP runtime.listen).
9. Reconcile policy: write CGROUP_POLICY map for every existing pod
   based on the routing rules.
10. Attach eBPF connect4 + skb_egress to runtime.cgroup.
11. Start tap (Phase B uprobes) if runtime.tap.enabled.
```

A successful startup ends with `INFO heimdall: heimdall ready
listen=0.0.0.0:12345`.

## Flags

```
heimdall serve [OPTIONS]
  --no-k8s          Disable Kubernetes informer; every cgroup
                    falls back to podRouting.default (HEIMDALL_NO_K8S env var)
```

`--config <PATH>` is *global* (any subcommand accepts it). When unset,
the daemon auto-discovers the config.

## Notable log lines

| Line | Meaning |
|---|---|
| `config loaded path=... connections=N pod_rules=M` | Parse OK |
| `all connections resolved connections=N` | Auth files read OK |
| `flow store ready path=...` | sqlite open + migrations done |
| `pod informer started` | watching kube-apiserver |
| `pod informer initial sync complete pods=K` | first reconcile possible |
| `eBPF connect4 attached cgroup=...` | redirect hook live |
| `eBPF skb_egress attached cgroup=...` | egress hook live |
| `policy: reconciled writes=N deletes=0 pods=K cgroups=N` | per-pod policy bytes pushed to BPF |
| `tap: started (Phase B) attached_libs=N` | uprobe tap on N libssl/Go binaries |
| `tunnel established` | per-flow info-level log |
| `relay error ...` | per-flow failure (SOCKS5 auth, conn refused, ...) |

## Diagnosing common startup failures

| Journal line | Cause |
|---|---|
| `connections registry: 'system' is reserved` | Don't declare `connections.system`; use `use: system` in a rule |
| `unknown use 'foo' in pod rule` | Misspelled or removed connection name |
| `cannot read passwordFile: ...` | Missing/permissions on `secrets/<name>.pw` |
| `failed to attach connect4` | Cgroup doesn't exist or insufficient capabilities (CAP_BPF + CAP_SYS_ADMIN required) |
| `informer init failed: ... falling back to default decision` | k8s unreachable; daemon still serves with default routing |

## Required capabilities

The systemd unit must grant:
- `CAP_BPF` — load + attach eBPF programs
- `CAP_NET_ADMIN` — manage network resources
- `CAP_SYS_ADMIN` — bpf() syscalls in some kernels
- `CAP_SYS_PTRACE` — readlink `/proc/<pid>/exe` for the tap's
  Go-binary scanner (across UIDs)

## Related skills

- `heimdall-status` — health check
- `heimdall-init` — bootstrap config the daemon reads
- `heimdall-flows` — query what the daemon recorded
