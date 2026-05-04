# Architecture

## Components

| Component | Crate / module | Role |
|---|---|---|
| eBPF programs | `heimdall-ebpf` | `connect4`, `skb_egress`, libssl uprobes, Go TLS uprobes — all in one ELF, embedded into the daemon binary |
| Userspace daemon | `heimdall` | loads / attaches eBPF, runs the relay, talks to k8s, drives the policy engine, serves the HTTP API |
| Web UI | `heimdall-ui` | React / MUI, `bun run build`, bundled into the daemon binary via `rust-embed` |
| Shared types | `heimdall-common` | `OrigDst`, `TapEvent`, `BypassEvent`, policy flag bits — `#![no_std]` so the eBPF crate can use them |
| Config schema | `heimdall-config` | YAML schema + validator — pure Rust, no kubernetes deps |

## End-to-end data flow

```
            ┌───────────────────────────── Pod ─────────────────────────────┐
            │                                                               │
            │   app process                                                 │
            │     │                                                         │
            │     │ connect(remote_ip:443)                                  │
            │     ▼                                                         │
            │   ┌──────────────────────── eBPF ────────────────────────┐   │
            │   │ connect4(BPF_CGROUP_INET4_CONNECT)                   │   │
            │   │  cgroup_id = bpf_get_current_cgroup_id()             │   │
            │   │  policy = CGROUP_POLICY[cgroup_id] or DEFAULT        │   │
            │   │                                                      │   │
            │   │  if is_kernel_bypass(remote_ip)                      │   │
            │   │     OR (policy & POLICY_REDIRECT_OFF):               │   │
            │   │       maybe emit BYPASS_EVENTS perf event            │   │
            │   │       return Ok                                      │   │
            │   │                                                      │   │
            │   │  // Else rewrite to relay:                           │   │
            │   │  COOKIE_MAP[socket_cookie] = OrigDst{remote, cgroup} │   │
            │   │  sock_addr.user_ip4   = relay_ip                     │   │
            │   │  sock_addr.user_port  = 12345                        │   │
            │   └──────────────────────────────────────────────────────┘   │
            │     │                                                         │
            │     │ TCP SYN                                                 │
            │     ▼                                                         │
            │   ┌─── eBPF skb_egress(BPF_CGROUP_INET_EGRESS) ───┐          │
            │   │  on first SYN: read assigned src_port,         │          │
            │   │  move COOKIE_MAP entry → PORT_MAP[src_port]    │          │
            │   └────────────────────────────────────────────────┘          │
            │                                                               │
            └───────────────────────────────────────────────────────────────┘
                  │
                  │  SYN to relay_ip:12345
                  ▼
   ┌──────────────────────────── Userspace daemon ───────────────────────────┐
   │                                                                          │
   │   relay (TCP listener)                                                   │
   │     │                                                                    │
   │     │ accept() → src_port → PORT_MAP[src_port] → OrigDst                │
   │     ▼                                                                    │
   │   PodInformer + CgroupResolver                                          │
   │     │  cgroup_id → pod_uid → labels/annotations                          │
   │     ▼                                                                    │
   │   router::resolve_decision(cfg, pod) → RoutingDecision { use_, observe }│
   │     │                                                                    │
   │     ▼                                                                    │
   │   SOCKS5 CONNECT to upstream → copy_bidirectional with the pod's stream │
   │     │                                                                    │
   │     │ insert flow_start row                                              │
   │     │ push flow_id to OpenFlowIndex[cgroup_id]                           │
   │     ▼                                                                    │
   │   sqlite (flows + messages tables)                                       │
   │     │                                                                    │
   │     ▼                                                                    │
   │   axum HTTP API + WebSocket → React UI                                   │
   │                                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
```

### Tap pipeline (Phase B)

Independent of the relay path. Fires on every libssl / Go TLS function
call **regardless** of whether the connection went through the relay.

```
process calls SSL_write(buf, n)
      │
      │  uprobe attached at libssl::SSL_write or
      │   crypto/tls.(*Conn).Write file offset
      ▼
   eBPF emit_tap()
      │  cgroup_id = bpf_get_current_cgroup_id()
      │  if (policy & POLICY_OBSERVE_OFF) return     ◄── observe gate
      │  bpf_probe_read_user(buf, ≤256 bytes)
      │  TAP_EVENTS.output(TapEvent{cgroup_id, dir, body, ...})
      ▼
   AsyncPerfEventArray (one buffer per CPU, in tap.rs)
      │  decode → ObservedTap
      ▼
   spawn_store_writer task
      │  flow_id = OpenFlowIndex[cgroup_id].latest()  ◄── correlation
      │  store.insert_message(InsertMessage{flow_id, body, ...})
      ▼
   sqlite.messages
```

### Policy plane

Independent control loop populating `CGROUP_POLICY` so the kernel
programs above can gate per-pod.

```
   /etc/heimdall/config.yaml
        │
        ▼
   HeimdallConfig (Routing.rules + Routing.default)
        │
   PodInformer (k8s watcher) + CgroupResolver (/sys/fs/cgroup walk)
        │      │
        │      └── cgroup_id ↔ pod_uid mapping
        │
        ▼
   PolicyEngine (heimdall/src/policy.rs)
     - subscribes to PodEvent stream (Upsert / Delete / InitDone)
     - reconciles every 5s as a safety net
     - encodes RoutingDecision → u8 flags
     - writes BPF CGROUP_POLICY[cgroup_id] = flags
```

### Bootstrap pass

One-shot, runs 2s after PolicyEngine is up. Closes the gap for
connections that already existed when the daemon started.

```
   for pod in informer.snapshot():
      pid = first proc in any of pod's cgroups
      for conn in /proc/<pid>/net/tcp where state == ESTABLISHED:
         insert_flow_start(connection_name="bootstrap", pod, dst)
         OpenFlowIndex[every cgroup of pod].push(flow_id)
```

After this pass, tap events from those long-lived connections find a
flow_id via OpenFlowIndex and end up correlated in the messages
table.

## Where each piece of state lives

| State | Where | Lifetime |
|---|---|---|
| eBPF maps (`COOKIE_MAP`, `PORT_MAP`, `CGROUP_POLICY`, `BYPASS_EVENTS`, `TAP_EVENTS`, `RELAY_ADDR`, `GO_READ_STATE`, `SSL_READ_STATE`) | kernel | until daemon exits |
| `flows` table | `/var/lib/heimdall/flows.db` | `runtime.flowRetentionSecs` (default 3 days) |
| `messages` table | same db | shared retention window |
| Pod label / cgroup cache | in-memory in daemon | refreshed by informer + 5s reconcile |
| OpenFlowIndex | in-memory `parking_lot::RwLock<HashMap>` | populated by relay + bypass + bootstrap, used by tap consumer |

## Process boundaries

- One systemd unit (`heimdall.service`) — relay + tap + API + UI all
  in the same binary.
- Caps required: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE` (last one for reading `/proc/<pid>/exe` symlinks
  belonging to other UIDs — needed for the Go-binary scanner). Set in
  `/etc/nixos/services/k0s/default.nix`.
- One TCP listener (12345 / relay), one HTTP listener (9999 / API +
  UI), one UDP listener (5358 / fake-IP DNS).

## What heimdall does NOT do

- **No MITM, no CA injection.** The relay sees the encrypted TLS
  byte stream just like any SOCKS5 tunnel; plaintext only comes from
  uprobes that observe the application's `SSL_*` calls before
  encryption / after decryption.
- **No per-connection filtering.** Policy granularity is per-pod
  (per-cgroup). Different connections from the same pod can't have
  different policies.
- **No pod-side reverse routing.** When `use: system` is chosen, the
  pod's connection bypasses heimdall entirely; the relay never sees
  it. We can still observe TLS plaintext (uprobes are independent of
  the relay path), but bytes_up / bytes_down stay zero on the
  synthetic flow row.
