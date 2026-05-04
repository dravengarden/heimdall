# Architecture

## Components

| Component | Crate / module | Role |
|---|---|---|
| eBPF programs | `heimdall-ebpf` | `connect4`, `connect6`, `udp4_sendmsg`, `udp6_sendmsg`, `skb_egress`, libssl uprobes, Go TLS uprobes, rustls uprobes — all in one ELF, embedded into the daemon binary |
| Userspace daemon | `heimdall` | loads / attaches eBPF, runs the relay (dual-stack), talks to k8s, drives the policy engine, GCs orphan CLI cgroups, serves the HTTP API |
| Web UI | `heimdall-ui` | React 19 / MUI, `bun run build`, bundled into the daemon binary via `rust-embed` |
| Shared types | `heimdall-common` | `OrigDst`, `TapEvent`, `BypassEvent`, `is_default_bypass{,6}`, policy flag bits — `#![no_std]` so the eBPF crate can use them |
| Config schema | `heimdall-config` | YAML / JSON / TOML / Nickel schema + validator — pure Rust, no kubernetes deps |

## End-to-end data flow

```
            ┌───────────────────────────── Pod ─────────────────────────────┐
            │                                                               │
            │   app process                                                 │
            │     │                                                         │
            │     │ connect(remote_ip:443)            (or :53 for DNS)      │
            │     ▼                                                         │
            │   ┌──────────── eBPF connect4 / connect6 ──────────────────┐ │
            │   │ cgroup_id = bpf_get_current_cgroup_id()                 │ │
            │   │ policy    = CGROUP_POLICY[cgroup_id] or DEFAULT         │ │
            │   │                                                          │ │
            │   │ DNS hijack gate (heimdall run with dns=fake):           │ │
            │   │   if (policy & DNS_HIJACK) and dport == 53:             │ │
            │   │     rewrite dst → DNS_ADDR_V{4,6}, return                │ │
            │   │                                                          │ │
            │   │ Bypass gate:                                             │ │
            │   │   if is_default_bypass{,6}(dst) OR (policy & REDIRECT_OFF):│
            │   │     maybe emit BYPASS_EVENTS perf event, return         │ │
            │   │                                                          │ │
            │   │ Else rewrite to relay:                                   │ │
            │   │   COOKIE_MAP[socket_cookie] = OrigDst{dst, family,      │ │
            │   │                                       cgroup_id}         │ │
            │   │   sock_addr.user_ip{4,6} = relay_ip{,6}                 │ │
            │   │   sock_addr.user_port    = 12345                         │ │
            │   └──────────────────────────────────────────────────────────┘ │
            │     │                                                         │
            │     │ TCP SYN to relay (or UDP for sendmsg DNS hijack)        │
            │     ▼                                                         │
            │   ┌─── eBPF skb_egress(BPF_CGROUP_INET_EGRESS) ──────────────┐ │
            │   │  detect IP version (byte-0 high nibble)                  │ │
            │   │   v4: protocol@9, IHL→TCP off                            │ │
            │   │   v6: walk next-header chain past extension headers      │ │
            │   │        (Hop-by-Hop / Routing / Fragment / DstOpts /      │ │
            │   │         Mobility / HIP / Shim6, max 8 hops) → TCP off    │ │
            │   │  read kernel-assigned src_port,                          │ │
            │   │  move COOKIE_MAP entry → PORT_MAP[src_port]              │ │
            │   └──────────────────────────────────────────────────────────┘ │
            │                                                               │
            └───────────────────────────────────────────────────────────────┘
                  │
                  │  SYN to relay_ip{,6}:12345
                  ▼
   ┌────────── Userspace daemon ─────────────────────────────────────────────┐
   │                                                                          │
   │   relay (dual-stack TcpListener on [::]:12345)                           │
   │     │                                                                    │
   │     │ accept() → src_port → PORT_MAP[src_port] → OrigDst                │
   │     │   (OrigDst.family discriminates v4 vs v6 destination)              │
   │     ▼                                                                    │
   │   PodInformer + CgroupResolver                                          │
   │     │  cgroup_id → pod_uid → labels/annotations  (None for non-pod)     │
   │     ▼                                                                    │
   │   cli_overrides.get(cgroup_id)                                          │
   │     │  hit → use heimdall-run-registered RunDecision                    │
   │     │  miss → router::resolve_pod_decision(cfg, pod) → PodDecision      │
   │     ▼                                                                    │
   │   fake-IP reverse lookup on OrigDst → SOCKS5 ATYP=0x03 hostname         │
   │     │  (when miss, fall back to ATYP=0x01 IPv4 / 0x04 IPv6 literal)     │
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

Independent of the relay path. Fires on every libssl / Go TLS / rustls
function call **regardless** of whether the connection went through
the relay.

```
process calls SSL_write(buf, n)  /  Go (*Conn).Write  /  rustls write
      │
      │  uprobe attached at libssl::SSL_write,
      │   crypto/tls.(*Conn).Write file offset (via .gopclntab),
      │   or rustls PlaintextSink::write (mangled symbol match)
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
   /etc/heimdall/heimdall.{ncl,toml,json,yaml}   (auto-discovered)
        │
        ▼
   HeimdallConfig (PodRouting.rules + PodRouting.default + cli.run)
        │
   PodInformer (k8s watcher) + CgroupResolver (/sys/fs/cgroup walk)
        │      │
        │      └── cgroup_id ↔ pod_uid mapping
        │
        ▼
   PolicyEngine (heimdall/src/policy.rs)
     - subscribes to PodEvent stream (Upsert / Delete / InitDone)
     - reconciles every 5s as a safety net
     - encodes PodDecision → u8 flags (REDIRECT_OFF / OBSERVE_OFF /
                                        NO_BYPASS_LOG / DNS_HIJACK)
     - writes BPF CGROUP_POLICY[cgroup_id] = flags
     - tracks `external` set so reconcile never wipes
       heimdall-run-registered cgroups (those are owned by the
       HTTP register/deregister lifecycle, not the pod informer)
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

### `heimdall run` lifecycle

`heimdall run` is a special CLI client of the same daemon, used to
wrap arbitrary commands so they go through a chosen connection.
Lifecycle in five phases:

```
1. Resolve RunDecision = (connection, observe, dns, tag) from
   cli.run.{default → profiles[NAME] → flags}.

2. Re-entry: if not already under user@<UID>.service/app.slice/,
   exec systemd-run --user --scope --quiet -- heimdall run
   --no-reentry … . This drops the process into a writable cgroup
   subtree (user-ns delegation; non-root works without sudo).

3. mkdir <parent>/heimdall-cli-<pid>-<rand>/ as a sibling cgroup.
   inode of that dir == cgroup_id (cgroup v2).

4. POST /api/cli/register {cgroup_id, connection, observe, dns}.
   Daemon: cli_overrides[cgroup_id] = decision; PolicyEngine
   .external += cgroup_id; CGROUP_POLICY BPF map row written
   (DNS_HIJACK bit if dns=fake).

5. fork()
     child:
       echo $$ > <cgroup>/cgroup.procs        # join the cgroup
       strip http_proxy / https_proxy env vars
       restore default SIGINT / SIGTERM handlers
       if dns=fake:
         unshare(CLONE_NEWUSER | CLONE_NEWNS)
         write uid_map / setgroups / gid_map
         mount(/, MS_PRIVATE | MS_REC)
         bind /tmp/heimdall-cli-nsswitch-<id>.conf → /etc/nsswitch.conf
              (hosts: files dns — skips nss-resolve)
         bind /tmp/heimdall-cli-resolv-<id>.conf   → /etc/resolv.conf
              (nameserver 127.0.0.1 — eBPF rewrites the :53 connect)
         bind /dev/null                            → /var/run/nscd/socket
              (forces glibc to skip nscd, hit our shimmed nsswitch)
       execvp(cmd, args)
     parent:
       waitpid(child)
       POST /api/cli/deregister?cgroup_id=N
       rm tmp shim files
       rmdir <cgroup>
       exit(child status)
```

If the parent dies abnormally (kill -9, OOM kill) before phase-5's
deregister-and-rmdir, the cgroup + BPF entry leak. The orphan-cgroup
GC (next subsection) reaps them.

### Orphan-cgroup GC

```
   tokio::time::interval(30s)
        │
        ▼
   walk /sys/fs/cgroup/user.slice (depth ≤ 6)
        │  match dirs starting with `heimdall-cli-`
        │
        ▼
   for each candidate:
      if cgroup.events: populated 0:
         cli_overrides.write().remove(cgroup_id)
         PolicyEngine.deregister_external(cgroup_id)
            ↳ external set -= cgroup_id
            ↳ CGROUP_POLICY BPF map row deleted
         rmdir(path)                  # needs CAP_DAC_OVERRIDE
                                      # because cgroup is user-owned
```

Idempotent and safe to run forever. Clean exits don't go through this
path because phase-5 of the run lifecycle does the cleanup
explicitly.

## Where each piece of state lives

| State | Where | Lifetime |
|---|---|---|
| eBPF maps (`COOKIE_MAP`, `PORT_MAP`, `CGROUP_POLICY`, `BYPASS_EVENTS`, `TAP_EVENTS`, `RELAY_ADDR{,6}`, `DNS_ADDR_V4`, `DNS_ADDR_V6`, `DNS_PORT_V6`, `GO_READ_STATE`, `SSL_READ_STATE`, `RUSTLS_READ_STATE`) | kernel | until daemon exits |
| `flows` table | `<runtime.stateDir>/flows.db` | `runtime.flowRetentionSecs` (default 3 days) |
| `messages` table | same db | shared retention window |
| Pod label / cgroup cache | in-memory in daemon | refreshed by informer + 5s reconcile |
| `cli_overrides` (`heimdall run` registrations) | in-memory `Arc<RwLock<HashMap<u64, PodDecision>>>` shared with HTTP API | until deregister or GC reap |
| `PolicyEngine.external` set | in-memory `Arc<RwLock<HashSet<u64>>>` | until deregister or GC reap |
| OpenFlowIndex | in-memory `parking_lot::RwLock<HashMap>` | populated by relay + bypass + bootstrap, used by tap consumer |
| Per-cgroup mount-ns shim files | `/tmp/heimdall-cli-{nsswitch,resolv}-<cgroup_id>.conf` | written by `heimdall run` parent before fork; deleted after waitpid |

## Process boundaries

- One systemd unit (`heimdall.service`) — relay + tap + API + UI + GC
  all in the same binary.
- Caps required: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`. Last two for the Phase B
  Go-binary scanner (readlink other UIDs' `/proc/<pid>/exe`) and the
  GC (rmdir user-owned heimdall-cli-* dirs).
- Two TCP listeners on the relay port (`runtime.listen` defaults to
  `0.0.0.0:12345`, auto-rewritten to `[::]:12345` for dual-stack
  accept), one HTTP listener (`runtime.apiListen`, default
  `127.0.0.1:9999`), one UDP listener (`runtime.dnsListen`, default
  `0.0.0.0:5358`).

## What heimdall does NOT do

- **No MITM, no CA injection.** The relay sees the encrypted TLS
  byte stream just like any SOCKS5 tunnel; plaintext only comes from
  uprobes that observe the application's `SSL_*` / Go / rustls calls
  before encryption / after decryption.
- **No per-connection filtering.** Policy granularity is per-cgroup
  (per-pod for k8s pods, per-`heimdall run` for CLI processes).
  Different connections from the same cgroup can't have different
  policies.
- **No pod-side reverse routing.** When `use: system` is chosen, the
  pod's connection bypasses heimdall entirely; the relay never sees
  it. We can still observe TLS plaintext (uprobes are independent of
  the relay path), but `bytes_up` / `bytes_down` stay zero on the
  synthetic flow row.
- **No JVM TLS taps yet.** Needs a JVMTI agent + native stub.
- **No relay for arbitrary UDP.** eBPF DNS hijack catches UDP `:53`
  specifically (when `dns: fake` is in effect for the cgroup); other
  UDP traffic goes direct.
