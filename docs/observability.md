# Observability — TLS plaintext capture (Phase B)

Heimdall's observability layer captures decrypted TLS payloads at
the application boundary using eBPF uprobes — no MITM, no CA
injection, no TLS termination. The relay sees only encrypted bytes
just like any SOCKS5 tunnel; the plaintext comes from intercepting
the application's own `SSL_*` / `crypto/tls.(*Conn).*` calls.

## Coverage matrix

| TLS implementation | Status | How it attaches | Notes |
|---|---|---|---|
| **OpenSSL `libssl.so.3`** | ✅ working | uprobe on `SSL_write`, uprobe + uretprobe on `SSL_read` | Found via dynamic linker / `/proc/<pid>/maps`, deduped by inode. Both directions captured. |
| **OpenSSL `libssl.so.1.1`** | ✅ working | same | Older Kong / older distros. Same symbol set. |
| **Go `crypto/tls.(*Conn).Write`** | ✅ working | uprobe at function entry | ABI Internal: receiver in RAX, slice (data, len, cap) in RBX/RCX/RDI. |
| **Go `crypto/tls.(*Conn).Read`** | ✅ working | uprobe at entry + uprobe at every RET site (no uretprobe) | uretprobes break Go's movable stacks, so we disassemble the function body with iced-x86 and attach a normal uprobe at every `FlowControl::Return` instruction. |
| **Go binaries built with `-ldflags="-s -w"`** | ✅ working | symbols come from `.gopclntab` instead of `.symtab` | rancher, kubelet, kube-apiserver, cilium, fleet, etc. — the runtime's own symbol table survives stripping. |
| **rustls** | ✅ implemented | uprobe at `<ConnectionCommon<T> as PlaintextSink>::write` entry; uprobe + uretprobe at `<Reader as std::io::Read>::read` | Symbol pattern match against the mangled name (`PlaintextSink$GT$5write17h`, `std..io..Read$GT$4read17h`). ABI: `RSI=buf.ptr`, `RDX=buf.len`; return is 16-byte `(RAX=tag, RDX=value)`. **Caveat:** symbol presence ≠ runtime usage — ClickHouse links rustls but its TLS path goes through statically-linked OpenSSL, so tap attaches successfully but never fires for that binary. Vector / edge-runtime / heimdall's own kube-rs client actually exercise it. |
| **JVM (`SunJSSE` provider)** | ❌ roadmap — see CHANGELOG | — | HotSpot's default TLS is pure Java (`sun.security.ssl.SSLEngineImpl.{wrap,unwrap}`), so existing libssl uprobes don't fire. Plan: a JVMTI agent (`-agentpath:`) that uses `RetransformClasses` to redirect those calls through a fixed-address native stub `heimdall_tls_observe(dir, buf, len)`, which we then uprobe like any libssl symbol. Requires modifying pod startup args (cleanest via mutating webhook injecting `JAVA_TOOL_OPTIONS`). |
| **BoringSSL static** | ❌ not implemented | — | Pixie's BoringSSL pattern-matching would work; deferred. |

## Limits and alternative approaches

The matrix above reports *what is implemented*, not *what is possible*.
Several implementations are hard for non-trivial reasons; this section
records what we considered and why we chose what we chose.

### JVM — why "not implemented" is "fundamentally hard"

uprobes attach to fixed machine-code addresses in an ELF text segment.
HotSpot's TLS implementation is **pure Java bytecode**
(`sun.security.ssl.SSLEngineImpl.{wrap,unwrap}`), and four properties
make it un-uprobable in the usual sense:

| Obstacle | Effect |
|---|---|
| Bytecode is not machine code | At process start, `SSLEngineImpl.wrap` exists in no `.text` segment; uprobe has nothing to attach to. |
| JIT addresses are unstable | After JIT, the method lives in the code cache at some address, but C1→C2 recompilation relocates it. |
| Method inlining | C2 frequently inlines the SSL methods into hot callers; the standalone function disappears entirely. |
| OSR (On-Stack Replacement) | A long loop can swap implementations mid-call; the address can move within a single invocation. |

Workarounds surveyed:

| Approach | Verdict |
|---|---|
| **`/tmp/perf-<pid>.map` + dynamic attach.** JVM emits JIT addresses via a `libperfmap.so` agent; user-space reads the file and re-attaches uprobes after every recompilation. | 🟡 Works in research demos, breaks on every recompilation. Production-fragile. This is the path `ecapture`'s experimental Java module took. |
| **JVMTI agent + `RetransformClasses`.** Load a Java agent that rewrites `SSLEngineImpl` bytecode to redirect through a fixed-address native stub `heimdall_tls_observe(dir, buf, len)`, then uprobe that stub. | ✅ Chosen for the roadmap. Stable across JVM versions because the stub is in our own ELF, not the JVM's code cache. Cost: requires injecting `JAVA_TOOL_OPTIONS` via mutating webhook. |
| **Hook native crypto libs.** If the JVM uses a native TLS provider (Conscrypt → BoringSSL, Wildfly Elytron → OpenSSL), uprobe `libssl.so` directly. | 🟡 Default OpenJDK uses pure-Java SunJSSE at the protocol layer; native is reached only for AES/SHA primitives, which is too low-level to recover frame boundaries. Useful only when a specific deployment opts in. |
| **GraalVM native-image.** AOT-compiled Java becomes a real ELF binary with stable symbols. | 🟡 Would work like Go. Almost no production Spring Boot deployments use native-image yet. |
| **ecapture-style keylog extraction.** uprobe internal JVM key-derivation paths to extract TLS master secrets, emit NSS keylog format, decrypt offline against a tcpdump pcap. | 🟡 Doesn't give real-time visibility — message bodies are recoverable only after the fact (capture + Wireshark). Disqualifies real-time routing and alerting on Java pods. Useful as a forensic complement, not a substitute for the JVMTI plan. Also fragile across JDK vendors/versions. |

The JVMTI plan trades operational complexity (startup-arg injection)
for engineering stability at the eBPF layer. Since heimdall already
needs a mutating-webhook story for CA distribution (M5 below),
reusing that mechanism to inject `JAVA_TOOL_OPTIONS` is cheap.

### rustls — implemented, but ABI-fragile

Listed ✅ above; restating the limits explicitly:

- Symbols match by mangled-name pattern (`PlaintextSink$GT$5write17h…`).
  New rustls major versions can rename or change visibility, silently
  breaking the match.
- Inlining at `-Crelease` with LTO can elide the function — the uprobe
  attaches successfully but never fires. Detected only by the "no
  events" symptom; there is no compile-time check.
- Generic monomorphization produces multiple specialized copies of
  `read`/`write` per binary. We attach all of them; binaries that
  instantiate rustls with many cipher/hash combinations inflate the
  attach count without inflating coverage.

### BoringSSL static — pattern-matching deferred

Pixie's approach (signature-match a stripped BoringSSL `.text` to
recover `SSL_read`/`SSL_write` prologues) would work and is
well-documented. Not implemented because the cluster's current
workloads don't exercise it; if a tap-required Chromium-derived or
custom-Node binary appears, this is the next module.

### Alternative path: MITM (M5) and why uprobe is preferred

The original observability plan (still on the roadmap as M5) was to
terminate TLS at the relay, mint per-connection certs, and forward
upstream over a fresh TLS session. That path has its own coverage
matrix, **complementary to and not a superset of** the uprobe path:

| Client | Reads OS truststore? | MITM viable? |
|---|---|---|
| Python `requests` / `httpx` / `pip` | ❌ uses `certifi` bundled CA list | Needs `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` injection per pod |
| Python stdlib `ssl` | ✅ | ✅ webhook-injected CA suffices |
| Go (`x509.SystemCertPool`) | ✅ | ✅ (distroless images without `/etc/ssl/certs/` excepted) |
| Node.js (default) | ❌ bundled roots; Node 23+ adds `--use-system-ca` | Needs `NODE_EXTRA_CA_CERTS` |
| Rust `rustls` + `webpki-roots` | ❌ Mozilla list compiled in | Cannot be satisfied without a code change |
| Rust `native-tls` | ✅ via OpenSSL/SChannel | ✅ |
| JVM | ❌ separate `cacerts` keystore | Needs init container or `keytool` invocation per pod |
| Anything with cert pinning | — | ❌ pinning rejects any synthetic cert |
| mTLS (client auth) | — | ❌ relay can't forge a valid client cert |

The uprobe path sidesteps all of this: heimdall never presents itself
as a TLS endpoint, so truststore configuration, pinning, and mTLS are
all transparent. The cost is the symbol-discovery problem the matrix
above documents. M5 remains on the roadmap for cases uprobes can't
reach (notably JVM, until JVMTI lands), but it is **complementary**,
not a replacement.

### Summary: when each path applies

| Workload | Preferred path | Fallback |
|---|---|---|
| OpenSSL-using apps (Python, C/C++, Ruby, most curl/git, default Node) | Phase B uprobe | none needed |
| Go services (any, including stripped via `.gopclntab`) | Phase B uprobe | none needed |
| rustls services | Phase B uprobe with attach-time symbol detection | L4-only if symbols inlined or absent |
| JVM services | JVMTI agent (planned) + uprobe on the injected stub | L4-only today; ecapture-style keylog as a forensic complement |
| BoringSSL static (Chromium, some Node) | Pattern-matching uprobe (planned) | L4-only |
| Apps with cert pinning or mTLS | Phase B uprobe (transparent regardless of pinning) | L4-only if uprobe symbols also unreachable |

L4-only is not a degraded mode — it is the honest answer when the
application's crypto boundary is opaque to us. Heimdall logs SNI,
byte counts, and connection metadata in that case rather than
pretending to see content it cannot.

## IPv4 / IPv6 / Unix-domain transport

Tap is **transport-agnostic**: uprobes fire at the application's
`SSL_*` / Go / rustls call boundary, before the bytes hit any socket.
A pod that opens a v6 TLS connection produces identical `TapEvent`
rows to one using v4; the tap layer never inspects the socket family.
Address-family details enter the picture only on the relay side
(see `architecture.md`'s data flow), where `OrigDst.family` is
preserved through `COOKIE_MAP` / `PORT_MAP` and surfaces as the
`atyp` column on the resulting flow row.

## How a tap event becomes a row

1. App makes a TLS call (e.g. `rancher` writes an HTTP/2 frame to
   apiserver).
2. uprobe fires: `emit_tap()` reads `bpf_get_current_cgroup_id()` and
   checks `CGROUP_POLICY[cgroup_id] & POLICY_OBSERVE_OFF`. If set,
   returns immediately — no perf-buffer overhead for silenced pods.
3. Otherwise allocates a `TapEvent` on the stack, copies up to 256
   bytes of plaintext via `bpf_probe_read_user`, calls
   `TAP_EVENTS.output()`.
4. Userspace `AsyncPerfEventArray` (one buffer per CPU) drains the
   event, decodes into `ObservedTap`, sends through an mpsc channel.
5. `spawn_store_writer` task pulls from the channel, looks up
   `OpenFlowIndex[cgroup_id]` for a flow_id, and writes a row to
   `messages` with that flow_id (or NULL if no flow exists).
6. UI's Live Tap polls `/api/messages` every second; per-flow tab
   queries `/api/flows/:id/messages`.

## Where flow_id correlation comes from

A `messages.flow_id` is set when the event's `cgroup_id` matches an
entry in the in-memory `OpenFlowIndex`. Three writers populate it:

1. **Relay** (proxied connections): every `insert_flow_start` for a
   redirected connection pushes its flow_id to
   `OpenFlowIndex[cgroup_id]`. Popped on `finish_flow`.
2. **Bypass consumer** (`bypass.rs`): listens to `BYPASS_EVENTS` perf
   events emitted by `connect4` for connections that took the
   bypass path (kernel-bypass CIDRs or `use: system`). Inserts a
   synthetic flow row tagged `connection_name = "bypass"` and
   pushes the id.
3. **Bootstrap pass** (`bootstrap.rs`): one-shot scan at daemon
   startup that reads each pod's `/proc/<pid>/net/tcp` and
   synthesizes a flow per ESTABLISHED v4 connection. Tagged
   `connection_name = "bootstrap"`. Without this, long-lived
   pre-existing connections (e.g. cluster controllers ↔ apiserver,
   kubelet's watch stream) would never get a flow_id. Currently v4
   only; v6 bootstrap (parsing `/proc/<pid>/net/tcp6`) is on the
   backlog, but the gap only matters for IPv6 connections that were
   already established when the daemon started — fresh connections
   correlate via the connect4/connect6 path.

Multi-container pods: bootstrap pushes the synthetic flow_id to
**every** cgroup of the pod, not just the one that owned the listing
pid, because the pause sandbox holds the netns while plaintext fires
from the application container.

## When `flow_id = NULL` is expected

- Host process firing a uprobe (e.g. `gopls`, `dnscrypt-proxy` on the
  host). Its cgroup isn't in `OpenFlowIndex` and shouldn't be —
  `DEFAULT_POLICY` drops these events at the eBPF layer anyway, so
  this case is rare.
- Race window: connect4 fires, tap fires before the bypass consumer's
  perf event drains. Order of milliseconds. Acceptable.
- Pods scheduled after daemon startup before bootstrap completes —
  also a small race window.

In all cases, the API response still attributes the message to the
correct pod via the cgroup_id → informer lookup, so the UI labels
remain useful.

## Uprobe attach details

### libssl

`tap::scan_libssl()` walks `/proc/*/maps`, finds entries matching
`libssl.so` or `libssl.so.<N>`, dedups by `(dev, inode)`, and resolves
the path through `/proc/<pid>/root/...` so containerized images are
handled correctly. aya's `UProbe::attach(Some("SSL_write"), 0,
target, None)` does symbol lookup against the libssl image's `.dynsym`
— libssl never strips these.

### Go (unstripped)

`gosym::looks_like_go(path)` checks for `.gopclntab`. If present,
`gosym::find_functions(path, ["crypto/tls.(*Conn).Write",
"crypto/tls.(*Conn).Read"])` walks the function table inside
`.gopclntab` (Go's runtime symbol table) and returns
`(vaddr, size, file_offset)` for each match. The file offset is
passed to `aya::UProbe::attach(None, file_offset, target, None)`.

This works for **all** Go binaries — stripped or not — because
`.gopclntab` is preserved by `-ldflags="-s -w"` (the runtime needs
it for stack traces).

### Go (stripped specifics)

Supported magic values for `.gopclntab`:

- `0xfffffff0` — Go 1.18, 1.19
- `0xfffffff1` — Go 1.20+

Header layout (64-bit, little-endian):

```
[0..4]   magic (u32)
[4..6]   pad
[6]      minLC (instruction quantum, unused)
[7]      ptrSize (must be 8)
[8..16]  nfunc
[16..24] nfiles  (unused)
[24..32] textStart  ← base for entryOff fields
[32..40] funcnameOffset
[40..48] cuOffset (unused)
[48..56] filetabOffset (unused)
[56..64] pctabOffset (unused)
[64..72] pclnOffset  ← function table starts here
```

Function table at `pclnOffset`: `nfunc + 1` entries of `(entryOff:
u32, funcOff: u32)`. The +1 sentinel gives the trailing function
its size. `funcInfo` at `pclnOff + funcOff` has its `nameOff` at
offset 4 (i32 into the funcname table at `funcnameOffset`).

Computing the attach offset:

```
vaddr        = textStart + entryOff
file_offset  = .text_file_off + (vaddr - .text_addr)
size         = next entry's entryOff - this entry's entryOff
```

### Go RET-offset trick (Read recv side)

uretprobes don't compose with Go's movable-stack runtime — the
trampoline anchor goes stale when goroutines copy frames during
stack growth. So we attach a regular uprobe at every `RET`
instruction in `crypto/tls.(*Conn).Read`:

1. Read function bytes from `.text` using the location from gosym.
2. Walk instructions with `iced_x86::Decoder`.
3. Record file offsets of every `FlowControl::Return` instruction.
4. Attach `go_tls_read_ret` at each — typically 7 sites per Go
   binary (the function compiles to an identical shape across builds).

At each RET site, `RAX` holds the syscall return value (the int Go's
`Read` returned) and we look up the buffer pointer stashed by the
entry uprobe.

## Tap-related config

```yaml
runtime:
  tap:
    enabled: true     # master switch — turn off /proc scan + uprobes
    persist: true     # write to messages table; off → journal-only
```

`tap.persist=false` is useful while validating a new probe: events
appear in `journalctl -u heimdall -f | grep "tap\["` without
piling up in sqlite. Switch to `true` for production.

## Operational metrics

How to gauge whether the tap is healthy:

```bash
# Number of unique attach points across libssl + Go binaries.
# Reported once at startup as `attached_libs=N`.
journalctl -u heimdall --since "10 minutes ago" | grep "tap: started"

# Per-pod message rate (last 60s):
sqlite3 /var/lib/heimdall/flows.db "
  SELECT f.namespace || '/' || f.pod_name AS pod, COUNT(*)
  FROM messages m LEFT JOIN flows f ON m.flow_id = f.id
  WHERE m.ts_us > strftime('%s','now') * 1000000 - 60000000
  GROUP BY pod ORDER BY 2 DESC;
"

# eBPF policy map state (which pods are silenced):
sudo bpftool map dump name CGROUP_POLICY \
  | awk '/value:/ {print $NF}' | sort | uniq -c
```

Healthy values: ~30+ attached_libs on a typical k0s node, growth
rate of 10–100 messages/sec across observed pods, BPF map size
matching pod count × ~3 cgroups each.
