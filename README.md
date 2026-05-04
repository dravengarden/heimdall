# heimdall

Transparent TLS-aware egress proxy + observability for Kubernetes pods,
powered by eBPF cgroup hooks and uprobes.

Routes outbound TCP through a SOCKS5 upstream **and** captures
decrypted TLS payloads at the application boundary — no MITM, no CA
injection, no per-application configuration.

Runs as a single binary (relay + tap + HTTP API + Web UI all in one),
typically deployed on Kubernetes nodes via systemd or as a privileged
DaemonSet.

---

## Core concepts: Flow vs Tap

Two ideas drive the entire data model. Most documentation references
both — internalize the distinction once and the rest follows.

### Flow — one TCP connection

A **flow** is a single TCP connection from a pod (or the host) to some
destination, tracked from `connect()` to close. One row in the
`flows` sqlite table per flow.

Captured fields: `pod_namespace/pod_name`, `cgroup_id`, `dst_ip:port`,
`dst_host` (when fake-IP DNS gave us a hostname), `connection_name`
(`default` / `conviva` / `bypass` / `bootstrap`), `upstream_addr`,
`bytes_up/down`, start + end timestamps, error.

A flow row is created in one of three places:

| Origin | `connection_name` | When |
|---|---|---|
| Relay path | `default`, `conviva`, … | eBPF redirected the connect4 to the relay; relay opens SOCKS5 to the named upstream |
| Bypass path | `bypass` | Connection is in the kernel-bypass CIDR set OR pod opted into `use: system`; relay never sees it but eBPF emits a perf event so we still record the metadata |
| Bootstrap pass | `bootstrap` | One-shot scan at daemon startup that synthesizes flows for connections already established before heimdall came up (rancher Watch streams, kubelet, controllers) |

The Web UI's **Flows** tab is this table.

### Tap (message) — one decrypted SSL_write / SSL_read

A **tap event** (stored as a `messages` row) is a single
`SSL_write()` or `SSL_read()` call captured by an eBPF uprobe at the
libssl / Go `crypto/tls.(*Conn).{Write,Read}` boundary, with up to
**256 bytes** of plaintext copied out via `bpf_probe_read_user`.

Captured fields: direction (`send` / `recv`), `body` (the truncated
plaintext), `total_len` (how big the call actually was), `cgroup_id`,
`tgid`, `ts_us`, and `flow_id` (foreign key to `flows`, may be NULL).

The Web UI's **Live Tap** tab is this stream in real time. The
**Plaintext** tab on a flow's detail drawer is the messages bound to
that flow.

### Flow ↔ message is 1 : N

```
Pod's long-lived TLS connection (flow #109)
   │
   ├─ 12:00:00.001  SEND  105 B  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
   ├─ 12:00:00.002  SEND   26 B  HTTP/2 SETTINGS frame
   ├─ 12:00:00.150  RECV  537 B  "HTTP/1.1 200 OK\r\nServer:..."
   ├─ 12:00:00.180  SEND  137 B  "GET /api/v1/pods?watch=true ..."
   ├─ 12:00:01.220  RECV  256 B  '{"type":"MODIFIED","object":{...'
   ├─ 12:00:02.310  RECV  256 B  '{"type":"MODIFIED","object":{...'
   │   ...
   └─ 12:30:00.000  connection closes — flow gets ts_end_us
```

One Rancher → kube-apiserver Watch is **one flow** but typically
hundreds to thousands of messages.

### How they correlate

`messages.flow_id` is set by joining on **`cgroup_id`**: when a tap
event fires, userspace looks up the most recent active flow for that
cgroup in `OpenFlowIndex` and stamps its id on the message.

`flow_id = NULL` is legitimate when:

- A host process triggers the uprobe (no kubepods cgroup → no flow).
- Race window between connect4 firing and the bypass-flow row landing.
- Bootstrap hasn't completed scanning when the first uprobe fires.

In all cases the API still attributes the message to a pod via
`cgroup_id → informer.lookup(uid)`, so the UI labels stay correct.

### Two orthogonal axes per pod

A pod's behavior toward heimdall is decided by two independent flags:

- **`use`** (proxy choice): `default`, `conviva`, or `system` (skip
  the relay entirely; let the kernel route natively).
- **`observe`**: whether tap events fire for this pod's cgroup.

Both come from `routing` rules in config, with annotation overrides:

```yaml
heimdall.io/connection: conviva | default | system
heimdall.io/observe:    "true"  | "false"
```

So a pod can route via the proxy while staying silenced (e.g. a
chatty controller), or skip the proxy and stay observed (a host-
network process you still want plaintext for). See
[docs/config.md](docs/config.md) for the full schema and every
combination.

---

## Documentation

Five focused documents under [`docs/`](docs/):

| Doc | Covers |
|---|---|
| [docs/README.md](docs/README.md) | Reading order + 90-second elevator pitch |
| [docs/architecture.md](docs/architecture.md) | Components, three control loops (relay / tap / policy), bootstrap pass, where each piece of state lives |
| [docs/config.md](docs/config.md) | Full `/etc/heimdall/config.yaml` schema, the orthogonal proxy × observe model, every combination as YAML, RoutingDecision → BPF flag byte mapping |
| [docs/observability.md](docs/observability.md) | Phase B tap: TLS coverage matrix, `.gopclntab` parsing for stripped Go binaries, the Go RET-offset uprobe trick, flow_id correlation rules |
| [docs/runbook.md](docs/runbook.md) | Daily build + deploy, expected startup log sequence, four common failure modes, every pod on the reference cluster classified |

---

## How it works (1-minute sketch)

```
Pod                             Host                          Upstream
───                             ────                          ────────
connect(1.2.3.4:443)
  │
  │  ┌─ eBPF connect4 (BPF_CGROUP_INET4_CONNECT) ────────────┐
  │  │  policy = CGROUP_POLICY[cgroup_id] or DEFAULT          │
  │  │  if kernel-bypass IP OR policy.REDIRECT_OFF:           │
  │  │      maybe emit BYPASS_EVENT  → userspace flow row     │
  │  │      return                                            │
  │  │  else:                                                  │
  │  │      COOKIE_MAP[socket_cookie] = OrigDst               │
  │  │      rewrite dst → relay_ip:12345                      │
  │  └────────────────────────────────────────────────────────┘
  │
  │  ┌─ eBPF skb_egress (CGROUP_INET_EGRESS) on first SYN ──┐
  │  │  read kernel-assigned src_port,                        │
  │  │  move COOKIE_MAP entry → PORT_MAP[src_port]            │
  │  └────────────────────────────────────────────────────────┘
  ▼
heimdall relay (127.0.0.1:12345)
  │  accept() → src_port → PORT_MAP[src_port] → OrigDst
  │  cgroup_id → pod_uid → routing.use → connection
  ▼
SOCKS5 CONNECT 1.2.3.4:443 ────────────────────────────────▶ 1.2.3.4:443
```

Plaintext capture is independent of the relay path. eBPF uprobes on
`SSL_write` / `SSL_read` (libssl) and `crypto/tls.(*Conn).Write` /
`Read` (Go) fire on every TLS call from any process whose cgroup has
`POLICY_OBSERVE_OFF` clear, copying up to 256 bytes of plaintext into
a perf event. Stripped Go binaries are handled by parsing
`.gopclntab` (Go's runtime symbol table) instead of the ELF symtab.

### Why eBPF instead of iptables TPROXY?

Traditional transparent proxies use iptables `TPROXY` +
`MASQUERADE`. On Kubernetes those two rules conflict: pod traffic
gets MASQUERADEd to the node IP, the proxy then marks it, return
packets get TPROXYed before conntrack can un-SNAT them, and the pod
never receives a reply.

`heimdall` hooks at the `connect()` syscall level — before the packet
is created. No TPROXY marks, no conntrack interference, no
MASQUERADE conflict.

---

## Requirements

| Requirement | Minimum |
|---|---|
| Linux kernel | **5.10+** (cgroup v2 + uprobes + perf event arrays) |
| cgroup | v2 unified hierarchy (`/sys/fs/cgroup`) |
| Capabilities | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` |
| SOCKS5 server | any (tested with v2raya, sing-box, hev-socks5-server) |

`CAP_SYS_PTRACE` is needed so the daemon can readlink other UIDs'
`/proc/<pid>/exe` while scanning for Go binaries to attach uprobes
to. Without it, the Go-tap scanner only sees its own processes.

---

## Build

```bash
# eBPF (different target — must build first; output is include_bytes!'d
# into the daemon)
( cd heimdall-ebpf && cargo +nightly build --release )

# UI (only when components or hooks change)
( cd heimdall-ui && bun run typecheck && bun run build )

# Daemon (embeds the eBPF object + UI bundle via rust-embed)
cargo build --release
```

See [docs/runbook.md](docs/runbook.md) for the deploy steps and
expected startup log sequence.

---

## Crate structure

```
heimdall/
├── heimdall/             # userspace daemon (CLI binary)
│   └── src/
│       ├── main.rs            # daemon entrypoint, relay loop
│       ├── api.rs             # axum HTTP API + WebSocket
│       ├── tap.rs             # libssl + Go uprobe attach + perf consumer
│       ├── gosym.rs           # .gopclntab parser (stripped Go)
│       ├── policy.rs          # PolicyEngine: rules → CGROUP_POLICY
│       ├── pod.rs             # CgroupResolver + PodInformer (kube-rs)
│       ├── router.rs          # resolve_decision (use, observe)
│       ├── store.rs           # sqlite: flows + messages
│       ├── bypass.rs          # synthesize flows for kernel-bypass paths
│       ├── bootstrap.rs       # one-shot startup scan of /proc/net/tcp
│       ├── dns.rs             # fake-IP DNS server (UDP)
│       └── cli/               # `heimdall flows`, `heimdall status`
├── heimdall-ebpf/        # eBPF kernel programs (bpfel-unknown-none)
│   └── src/main.rs
├── heimdall-common/      # shared types (no_std + std features)
├── heimdall-config/      # YAML schema + validator
├── heimdall-ui/          # React 19 + MUI + bun + Vite
└── docs/                 # design + ops documentation
```

---

## Limitations

- **TCP only.** UDP isn't intercepted; use a DoH proxy for DNS.
- **IPv4 only.** IPv6 hooks would need a parallel `connect6`
  program — not yet implemented.
- **rustls is not yet tapped.** Symbols are mangled per-binary and
  the read path is inlined; deferred. See
  [docs/observability.md](docs/observability.md) for the full
  coverage matrix.
- **JVM TLS is not tapped.** Needs a JVMTI agent + native stub.
- **Linux only.** cgroup eBPF hooks are Linux-specific.

---

## License

MIT
