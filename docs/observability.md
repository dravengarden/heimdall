# Observability — TLS plaintext capture (Phase B)

Heimdall's observability layer captures decrypted TLS payloads at
the application boundary using eBPF uprobes — no MITM, no CA
injection, no TLS termination. The relay sees only encrypted bytes
just like any SOCKS5 tunnel; the plaintext comes from intercepting
the application's own `SSL_*` / `crypto/tls.(*Conn).*` calls. Where
the uprobe path can't reach (stripped static binaries, JVM), heimdall
falls back to an honest L4 + SNI record so flows still carry a
hostname.

## Feature matrix

What heimdall's TLS observability does and doesn't do, today.

| Capability | Status | Mechanism |
|---|---|---|
| **Plaintext capture: OpenSSL `libssl.so` (1.1, 3.x)** | ✅ shipped | dynsym lookup of `SSL_read`/`SSL_write`; both directions captured |
| **Plaintext capture: Go `crypto/tls`** | ✅ shipped | `.gopclntab` parsing + RET-offset uprobes; works on stripped Go binaries (rancher / cilium / kubelet) |
| **Plaintext capture: rustls (unstripped)** | ✅ shipped | Coroot-style substring match (`rustls` + `Reader`/`Writer` + `read`/`write`); covers rustls 0.21 (`PlaintextSink`) through current (`Writer<>`) |
| **Plaintext capture: BoringSSL static (unstripped)** | ✅ shipped | `.rodata` `BoringSSL` marker + `.symtab`/`.dynsym` lookup; reuses the existing OpenSSL eBPF programs since the C ABI is bit-identical |
| **Plaintext capture: stripped static binaries (Bun / Deno / Envoy / Chromium-derived)** | 🟡 not attempted | No OSS tool ships a working answer here — see *Limits and alternative approaches* |
| **Plaintext capture: JVM** | 🟡 deferred | Roadmap: JVMTI agent + native uprobe stub |
| **SNI hostname fallback** | ✅ shipped | TLS ClientHello peek in the relay; recovers hostname for IP-literal connections that skipped fake-IP DNS, regardless of how stripped the binary is |
| **Live re-scan** | ✅ shipped | 30 s tokio interval re-runs all four TLS scanners; pods born after daemon startup are picked up automatically |
| **Bootstrap of pre-existing connections (IPv4 + IPv6)** | ✅ shipped | `/proc/<pid>/net/{tcp,tcp6}` parse; `::ffff:V4` mapped entries filtered to avoid double-counting |
| **Cert pinning / mTLS** | ✅ transparent | uprobe path reads the application's own buffer; no MITM, no synthetic cert, no truststore manipulation |
| **MITM observability path (M5)** | 🟡 planned | Complementary to uprobe — see *Limits and alternative approaches* |

## Querying tap state from AI / scripts

Two places AI consumers can read tap status:

### 1. `/api/status` HTTP endpoint (richest)

Hit `GET http://127.0.0.1:9999/api/status` and read the `tap` field:

```json
{
  "tap": {
    "attached": 48,
    "scanners": {
      "libssl": 10,
      "go":     35,
      "rustls": 2,
      "boringssl_static": 1
    },
    "recent_failures": [
      {
        "scanner": "rustls",
        "path": "/proc/12345/root/usr/local/bin/some-binary",
        "error": "rustls write symbol absent (likely stripped)",
        "ts_us": 1762391283482911
      }
    ],
    "rescan": {
      "enabled": true,
      "period_secs": 30,
      "ticks": 412,
      "last_tick_ts_us": 1762391280000000,
      "panics": 0
    }
  }
}
```

| Field | Use it for |
|---|---|
| `attached` / `scanners.<name>` | "How many TLS endpoints does heimdall currently observe, broken out by implementation?" |
| `recent_failures` (cap 32) | "Why didn't pod X's binary get attached?" — search for path components. Stripped binary errors land here as soon as the scanner detects them (well-known shape: `*write symbol absent`). |
| `rescan.enabled` | False = pods born after daemon start are NOT being picked up. Indicates a misconfig or `tap.enabled = false`. |
| `rescan.last_tick_ts_us` + `rescan.period_secs` | Health probe: `(now_us - last_tick_ts_us) / 1_000_000 > period_secs * 2` means rescan stalled. |
| `rescan.panics` | `> 0` is always a bug — the rescan loop caught and recovered, but something is structurally wrong. Open an issue. |

### 2. Per-flow signal in the `flows` table (cheap; no daemon required)

For "given a flow, can I expect plaintext for it?", read the row directly:

| `atyp` | `dst_host` | What it means |
|---|---|---|
| `domain` | non-NULL | fake-IP DNS hit; pod connected by hostname. Plaintext **likely** captured if the pod's binary has tap support. |
| `ip` / `ip6` | non-NULL | **SNI fallback** fired — pod connected by IP literal but the TLS ClientHello carried `server_name`. Plaintext **not captured**; the hostname is the best we have. |
| `ip` / `ip6` | NULL | Pod connected by IP literal **and** sent no SNI (per RFC 6066, browsers / curl / Bun's `fetch()` to an IP all do this). Plaintext almost certainly not captured. |

Cross-check with `messages`:

```sql
-- Did this flow actually capture plaintext?
SELECT COUNT(*) FROM messages WHERE flow_id = ?;   -- 0 rows = no plaintext
```

Together: `(atyp, dst_host, message-count)` gives AI a complete view of "what the daemon could observe for this flow" without asking the daemon.

## TLS implementation coverage

| TLS implementation | Status | How it attaches | Notes |
|---|---|---|---|
| **OpenSSL `libssl.so.3`** | ✅ working | uprobe on `SSL_write`, uprobe + uretprobe on `SSL_read` | Found via dynamic linker / `/proc/<pid>/maps`, deduped by inode. Both directions captured. |
| **OpenSSL `libssl.so.1.1`** | ✅ working | same | Older Kong / older distros. Same symbol set. |
| **Go `crypto/tls.(*Conn).Write`** | ✅ working | uprobe at function entry | ABI Internal: receiver in RAX, slice (data, len, cap) in RBX/RCX/RDI. |
| **Go `crypto/tls.(*Conn).Read`** | ✅ working | uprobe at entry + uprobe at every RET site (no uretprobe) | uretprobes break Go's movable stacks, so we disassemble the function body with iced-x86 and attach a normal uprobe at every `FlowControl::Return` instruction. |
| **Go binaries built with `-ldflags="-s -w"`** | ✅ working | symbols come from `.gopclntab` instead of `.symtab` | rancher, kubelet, kube-apiserver, cilium, fleet, etc. — the runtime's own symbol table survives stripping. |
| **rustls (unstripped)** | ✅ implemented | uprobe at the rustls write entry; uprobe + uretprobe at the rustls read entry | Substring-tuple symbol match (Coroot's approach): write needs `rustls` + (`Writer` ∨ `PlaintextSink`) + `write` (excluding `write_vectored`/`write_all`/`write_fmt`/`write_str`); read needs `rustls` + `Reader` + `read` (excluding `read_to_end`/`read_to_string`/`read_exact`/`read_buf`/`read_vectored`). Covers rustls 0.21's `PlaintextSink` API and the post-0.22 `Writer<>` API in one filter. ABI: `RSI=buf.ptr`, `RDX=buf.len`; return is 16-byte `(RAX=tag, RDX=value)`. **Caveat:** symbol presence ≠ runtime usage — ClickHouse links rustls but its TLS path goes through statically-linked OpenSSL, so tap attaches successfully but never fires for that binary. Vector / edge-runtime / heimdall's own kube-rs client actually exercise it. |
| **BoringSSL static (unstripped)** | ✅ implemented | reuse OpenSSL `ssl_write`/`ssl_read_enter`/`ssl_read_exit` programs at file offsets resolved from `.symtab`/`.dynsym` | Two-stage detection: (1) `BoringSSL` literal in `.rodata` (high-confidence marker for static-linked BoringSSL; absent from non-BoringSSL OpenSSL builds); (2) `SSL_write`/`SSL_read` symbol lookup. ABI is bit-identical to OpenSSL so no new eBPF programs are needed. Hits e.g. RedisInsight's bundled Node binary. |
| **rustls / BoringSSL (stripped static)** | ❌ not attempted | — | Both symbol tables are gone in production builds (Bun, Deno, current Node releases, Envoy, Chromium-derived). No OSS tool ships a working answer for this — see *Limits and alternative approaches*. SNI fallback covers these binaries' hostnames at the relay layer. |
| **JVM (`SunJSSE` provider)** | ❌ not implemented | — | HotSpot's default TLS is pure Java (`sun.security.ssl.SSLEngineImpl.{wrap,unwrap}`), so existing libssl uprobes don't fire. See *Limits and alternative approaches* below. |

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

### rustls — substring-tuple match, ABI-fragile

Listed ✅ above. The matcher uses Coroot's substring-tuple approach
rather than exact mangled-name patterns:

- **Write:** any symbol containing `rustls` + (`Writer` OR
  `PlaintextSink`) + `write`, minus the `io::Write` helper methods
  (`write_vectored`, `write_all`, `write_fmt`, `write_str`).
- **Read:** any symbol containing `rustls` + `Reader` + `read`, minus
  helper methods (`read_to_end`, `read_to_string`, `read_exact`,
  `read_buf`, `read_vectored`).

Covers both eras of the rustls public API: 0.21 and earlier expose a
`PlaintextSink` trait, 0.22+ replaced it with a `Writer<'_, T>`
struct that implements `std::io::Write`. The substring tuple is
strictly more permissive than the old exact pattern — measurable side
effect: heimdall's own kube-rs binary used to log "rustls Read::read
symbol absent (likely inlined); recv-side skipped"; with substring
matching the recv-side now attaches.

Remaining limits:

- **Stripped binaries** (e.g. Deno alpine, edge-runtime release
  builds) lose `.symtab` entirely. Symbol substring matching can't
  recover them. Coverage for these falls to the SNI fallback path.
- **LTO inlining** at `-Crelease` can absorb the rustls function into
  callers; the uprobe attaches but never fires. Same silent-no-fire
  symptom as before.
- **Generic monomorphization** produces multiple specialized copies;
  we attach the first match. Binaries with many cipher/hash
  combinations may have more attached symbols than there are real
  call sites, but no behaviour difference.

### BoringSSL static — implemented for unstripped, deferred for stripped

Two-stage scan in `tap::find_boringssl_offsets`:

1. **Marker check.** Scan the `.rodata` section for the literal
   `BoringSSL`. The string is part of `OPENSSL_VERSION_TEXT` and
   several internal error strings; non-BoringSSL builds (vendored
   OpenSSL, no SSL at all) don't carry it.
2. **Symbol lookup.** Find `SSL_write` and `SSL_read` in `.symtab`,
   falling back to `.dynsym`. Compute file offsets and reuse the
   existing `ssl_write` / `ssl_read_enter` / `ssl_read_exit` eBPF
   programs at those offsets.

What's still not covered:

- **Stripped static BoringSSL builds** (Bun, current Node releases,
  Envoy, Chromium-derived). `.symtab` is wiped at link time; the
  prologue bytes are still in `.text` but there's no index to find
  them. The community state of the art on this has two narrow
  workarounds and no general solution:

| Tool | Approach to stripped static BoringSSL | Where it stops |
|---|---|---|
| **Pixie / Stirling** | Per-Node-version offset templates (`kNodeOpenSSLUProbeTmplsV12_3_1`, `V15_0_0`) for the *Node.js* TLSWrap struct only | Doesn't cover Bun, Envoy, or arbitrary stripped consumers; explicit "stripped binaries unsolved" admission in their 2023 blog |
| **ecapture** | `utils/boringssl_android_offset.sh` clones the Android BoringSSL repo, compiles an offset probe, ships per-platform kern objects (`a_13`, `a_14`, `a_15`) | Android-only; unrelated to desktop Bun / Chromium |
| **Coroot, DeepFlow, Beyla, Tetragon, Tracee** | Don't attempt; either drop to L4-only or punt to ecapture | "Cannot attach to a function that can't be found" — Pixie's words |

  Heimdall takes the consensus position: don't attempt prologue
  signature engineering, use SNI fallback to keep flows tagged with
  hostnames even when plaintext is unrecoverable.

- **LTO-elided BoringSSL.** Aggressive LTO can absorb `SSL_write`
  into a single caller; the symbol points at code that's no longer
  the canonical entry. Same silent-no-fire mode as rustls.

### SNI fallback — hostname recovery for opaque TLS

When the relay's fake-IP DNS doesn't have a hostname for the
destination IP (i.e. the pod connected by literal IP, not via name
resolution), heimdall now peeks at the first TLS record on the
accepted client socket and parses the SNI server_name extension.
Implementation: `src/sni.rs` (~200 LoC including unit tests).

Properties:

- **Non-destructive.** Uses `TcpStream::peek()` so the bytes stay in
  the kernel buffer for the upstream-forwarding stage.
- **Time-bounded.** 150 ms timeout — non-TLS or extremely slow
  clients return `None` rather than stalling the relay's accept
  fan-out.
- **Stripped-binary-friendly.** Doesn't depend on any symbol or
  eBPF state in the pod. Works regardless of which TLS library is
  in use.
- **Covers the gap exactly where the tap layer fails.** Bun,
  Deno, Envoy, Chromium-derived crawlers — even when their
  binaries are stripped and we can't decode plaintext, the flow
  row gets a `dst_host` field from the SNI extension.

Limits:

- Clients that connect by IP literal often **don't send SNI**
  (per RFC 6066: "Literal IPv4 and IPv6 addresses are not permitted
  in 'HostName'."). Browsers, curl, Bun's `fetch()` to an IP all
  fall in this bucket. SNI fallback only fires when the client
  explicitly set a `servername` despite the IP destination —
  service meshes and apps with hard-coded `host → IP` mappings.
- TLS 1.3 ClientHello can be encrypted (ECH); when ECH is in use,
  the outer SNI is a generic alias and the real hostname is
  unrecoverable. Not an issue against current cluster workloads.

### Live re-scan

`tap::spawn_rescan` runs every 30 s after daemon startup, re-running
`scan_libssl()` / `scan_go_tls()` / `scan_rustls()` /
`scan_boringssl_static()` and attaching uprobes only to binaries
whose `(dev, inode)` is not already in the shared `AttachedSet`.
Replaces the previous "scanned once at startup, restart heimdall to
pick up new pods" behaviour.

Trade-off accepted: pods born between ticks miss up to 30 s of TLS
correlation before the next pass attaches. Per-flow correlation
catches up retroactively once attached, since the BPF programs only
need to be live by the time the pod issues a TLS call worth
capturing — long-lived TLS streams (apiserver Watch, leader
election) benefit immediately.

Inotify / fanotify on `/sys/fs/cgroup/kubepods` would be more
responsive but adds significant complexity (cgroup-event correlation
across pod lifecycles). 30 s polling is the simpler-than-Pixie
approach that works in practice.

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
| OpenSSL-using apps (Python, C/C++, Ruby, most curl/git, default Node) | Phase B uprobe | — |
| Go services (any, including stripped via `.gopclntab`) | Phase B uprobe | — |
| rustls services (unstripped) | Phase B uprobe (substring-tuple match) | SNI fallback if symbols inlined; L4 metadata otherwise |
| rustls services (stripped — Deno alpine, edge-runtime release) | SNI fallback | L4 metadata only |
| BoringSSL static (unstripped — RedisInsight node) | Phase B uprobe (reuses OpenSSL programs) | SNI fallback if symbols inlined |
| BoringSSL static (stripped — Bun, current Node, Envoy, Chromium-derived) | SNI fallback | L4 metadata only |
| JVM services | SNI fallback today; JVMTI agent on the roadmap | L4 metadata; ecapture-style keylog as forensic complement |
| Apps with cert pinning or mTLS | Phase B uprobe (transparent regardless of pinning) | SNI fallback for stripped pinned apps |

L4-only is not a degraded mode — it is the honest answer when the
application's crypto boundary is opaque to us. The flow row still
carries the SNI hostname (when sent), pod identity, byte counts,
and timing; only the message body is unrecoverable.

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
   startup that reads each pod's `/proc/<pid>/net/tcp` **and**
   `/proc/<pid>/net/tcp6` and synthesizes a flow per ESTABLISHED
   connection. Tagged `connection_name = "bootstrap"`, with `atyp`
   set to `"ip"` or `"ip6"` depending on the source file. The v6
   parser drops `::ffff:V4` mapped entries to avoid double-counting
   against the v4 pass on dual-stack sockets. Without this,
   long-lived pre-existing connections (cluster controllers ↔
   apiserver, kubelet's watch stream, dual-stack ingresses) would
   never get a flow_id.

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
