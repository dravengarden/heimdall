# heimdall — docs

Transparent TLS-aware egress proxy + observability for Kubernetes pods,
built on eBPF and aya.

## Reading order

1. **[architecture.md](architecture.md)** — what the components are and
   how data flows from pod connect() through plaintext capture into the
   UI.
2. **[config.md](config.md)** — `/etc/heimdall/config.yaml` schema, the
   orthogonal `proxy` × `observe` model, and every routing case
   (matched against the actual pods on a typical k0s node).
3. **[observability.md](observability.md)** — Phase B TLS plaintext
   tap: which TLS implementations are supported (libssl, Go), how
   `.gopclntab` parsing handles stripped binaries, what doesn't yet
   work (rustls, Java).
4. **[runbook.md](runbook.md)** — daily ops: deploying a new build,
   reading the UI, debugging "why isn't this pod showing up", and a
   reference of where each piece of state lives.

## What heimdall is, in 90 seconds

A pod opens a TCP connection. eBPF's `connect4` hook intercepts it
**inside the pod's cgroup** before the kernel routes the packet, looks
up a per-cgroup policy in a BPF map, and either:

- Rewrites the destination to `127.0.0.1:12345` so the relay can take
  over → relay does SOCKS5 to v2raya / Mac / chosen upstream.
- Lets the kernel route natively (`use: system`) — pod-internal
  traffic, kube-apiserver chatter, anything in the kernel-bypass CIDR
  list.

Independently of the proxy choice, **every pod also has an `observe`
flag**. When on, libssl uprobes (for OpenSSL-using processes) and Go
uprobes (for Go binaries that link `crypto/tls`) capture decrypted
payloads on `SSL_write` / `SSL_read` and stream them through a perf
event array into a sqlite store. The Web UI shows the live decrypted
plaintext alongside the connection metadata.

Both axes are configurable per-rule and per-pod (annotations override
rules), so noisy infrastructure pods (kube-apiserver, controllers,
data stores) can be silenced while user workloads stay observed.
