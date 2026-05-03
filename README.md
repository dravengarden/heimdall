# heimdall

Transparent SOCKS5 egress proxy for Linux, powered by eBPF cgroup hooks.

Routes **all outbound TCP connections** through a SOCKS5 server — no per-application configuration, no `HTTP_PROXY` env vars, no iptables rules.

Works standalone as a CLI tool, or deployed as a Kubernetes **DaemonSet** to transparently proxy every pod on a node.

---

## How It Works

```
Process / Pod                    Host                          SOCKS5 Server
─────────────                    ────                          ─────────────
connect(1.2.3.4:443)
    │
    │  ┌─ eBPF BPF_CGROUP_INET4_CONNECT hook ─────────────┐
    │  │  1. Check destination: LAN/cluster? → pass through │
    │  │  2. External? Save original dst in BPF map         │
    │  │  3. Rewrite connect() target → 127.0.0.1:12345    │
    │  └────────────────────────────────────────────────────┘
    │
    │  ┌─ eBPF BPF_CGROUP_SOCK_OPS / ACTIVE_ESTABLISHED ──┐
    │  │  After TCP handshake: kernel knows ephemeral port  │
    │  │  Move BPF map entry: cookie → src_port            │
    │  └────────────────────────────────────────────────────┘
    │
    ▼
heimdall relay (127.0.0.1:12345)
    │  accept() → peer port → lookup BPF map → original dst
    │
    ▼
SOCKS5 server (--socks5)  ──────────────────────────────────▶  1.2.3.4:443
    CONNECT 1.2.3.4 443
```

### Why eBPF instead of iptables TPROXY?

Traditional transparent proxies use iptables `TPROXY` + `MASQUERADE`. On Kubernetes these two rules conflict: pod traffic gets MASQUERADEd to the node IP, v2raya then marks it with `0x40`, return packets get TPROXYed before conntrack can un-SNAT them, and the pod never receives a reply.

`heimdall` hooks at the `connect()` **syscall level** — before the packet is ever created. No TPROXY marks, no conntrack interference, no MASQUERADE conflict. The eBPF hook and the userspace relay use two independent TCP connections, so conntrack state is never polluted.

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| Linux kernel | **5.7+** (cgroup v2 + BPF_CGROUP_INET4_CONNECT stable) |
| cgroup | **v2** unified hierarchy (`/sys/fs/cgroup`) |
| Capabilities | `CAP_BPF` + `CAP_NET_ADMIN` (or `CAP_SYS_ADMIN` on older kernels) |
| SOCKS5 server | Any (tested with v2raya, sing-box, xray) |

---

## Building

The project has two compilation steps because the eBPF kernel code targets a different architecture.

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the eBPF target
rustup target add bpfel-unknown-none

# Required for building core without std
cargo install cargo-bpf  # or use nightly with -Z build-std
```

### Build

```bash
# Step 1: compile the eBPF kernel programs
cargo build -p heimdall-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

# Step 2: compile the userspace binary (embeds the eBPF object above)
cargo build -p heimdall --release

# Binary is at:
./target/release/heimdall
```

### Docker

```bash
docker build -t heimdall:latest .

# Or pull from registry (after CI publishes it):
# docker pull ghcr.io/your-org/heimdall:latest
```

---

## Usage

### CLI

```bash
# Basic: proxy all external TCP through a local SOCKS5 server
sudo heimdall --socks5 127.0.0.1:1080

# Custom listen port (if 12345 is taken)
sudo heimdall --socks5 127.0.0.1:1080 --listen 127.0.0.1:19999

# Attach to a specific cgroup subtree (instead of root)
sudo heimdall --socks5 127.0.0.1:1080 \
  --cgroup /sys/fs/cgroup/kubepods.slice

# Extra bypass CIDRs (default already includes RFC-1918, loopback, link-local)
sudo heimdall --socks5 127.0.0.1:1080 --bypass 100.64.0.0/10,fd00::/8

# All options via environment variables (useful for containers)
SOCKS5_ADDR=127.0.0.1:1080 CGROUP_PATH=/sys/fs/cgroup sudo -E heimdall
```

```
USAGE:
    heimdall [OPTIONS] --socks5 <ADDR>

OPTIONS:
    --socks5 <ADDR>       SOCKS5 server address [env: SOCKS5_ADDR]
    --listen <ADDR>       Relay listener address [env: LISTEN_ADDR] [default: 127.0.0.1:12345]
    --cgroup <PATH>       cgroup v2 mount point  [env: CGROUP_PATH] [default: /sys/fs/cgroup]
    --bypass <CIDRS>      Extra bypass CIDRs, comma-separated [env: BYPASS_CIDRS]
    -h, --help            Print help
    -V, --version         Print version
```

### Default bypass list

Traffic to these ranges is **never** proxied (passed through directly):

| CIDR | Purpose |
|------|---------|
| `127.0.0.0/8` | Loopback |
| `10.0.0.0/8` | RFC-1918 + typical pod/service CIDRs |
| `172.16.0.0/12` | RFC-1918 |
| `192.168.0.0/16` | RFC-1918 / LAN |
| `169.254.0.0/16` | Link-local |

---

## Kubernetes Deployment

`heimdall` runs as a privileged **DaemonSet** — one pod per node, covering all pods on that node transparently.

### Quick start

```bash
# 1. Set your SOCKS5 server address
kubectl create secret generic heimdall-config \
  --from-literal=socks5-addr=127.0.0.1:20170 \
  -n kube-system

# 2. Deploy
kubectl apply -f deploy/daemonset.yaml

# 3. Verify
kubectl -n kube-system get pods -l app=heimdall
```

### Why privileged?

The DaemonSet needs:
- `CAP_BPF` / `CAP_SYS_ADMIN` — to load eBPF programs into the kernel
- `CAP_NET_ADMIN` — to modify network configuration
- `/sys/fs/cgroup` host mount — to attach eBPF hooks to the root cgroup
- `hostPID: true` — to access the host cgroup namespace

### Architecture with Kubernetes

```
Node
├── heimdall DaemonSet pod (privileged)
│   ├── eBPF hook → root cgroup (/sys/fs/cgroup)
│   │              covers ALL pods on this node
│   └── Relay listener on 127.0.0.1:12345
│
├── Pod A              → external TCP → [eBPF redirects] → heimdall → SOCKS5
├── Pod B              → cluster TCP → [eBPF bypasses] → direct
└── Pod C              → LAN TCP    → [eBPF bypasses] → direct
```

---

## Crate Structure

```
heimdall/
├── heimdall/          # Userspace daemon (CLI binary)
│   └── src/main.rs
├── heimdall-ebpf/     # eBPF kernel programs (bpfel-unknown-none target)
│   └── src/main.rs
├── heimdall-common/   # Shared types (no_std compatible)
│   └── src/lib.rs
└── deploy/
    └── daemonset.yaml   # Kubernetes DaemonSet manifest
```

### BPF map flow

```
connect4 hook
  COOKIE_MAP[socket_cookie] = (orig_ip, orig_port)

sock_ops hook (ACTIVE_ESTABLISHED_CB)
  PORT_MAP[ephemeral_src_port] = COOKIE_MAP[socket_cookie]
  delete COOKIE_MAP[socket_cookie]

userspace relay (after accept)
  orig = PORT_MAP[peer_port]
  delete PORT_MAP[peer_port]
  SOCKS5 CONNECT orig.ip:orig.port
```

---

## Limitations

- **TCP only** — UDP is not intercepted (use a DNS-over-HTTPS proxy like `dnscrypt-proxy` for DNS)
- **IPv4 only** — IPv6 support planned
- **Linux only** — cgroup eBPF hooks are Linux-specific
- Kernel **5.7+** required for stable `BPF_CGROUP_INET4_CONNECT`

---

## License

MIT
