# Product contract

This document is the single normative summary of Heimdall's product boundary.
More detailed documents may explain implementation and operation, but they
must not contradict these requirements.

## Purpose

Heimdall runs one CLI command and its descendants through an explicit egress
policy. It is a command-scoped TCP/UDP proxy and an optional transparent TLS
inspection boundary for terminal tools and AI agents. It is not a host-wide
VPN or an application control plane.

## Distribution and lifecycle

1. Installation produces one `heimdall` executable. Linux embeds both its eBPF
   object and native interposition library; macOS embeds its native
   interposition library. No companion is required for a released backend.
2. `heimdall run -- COMMAND` owns one foreground session. The Linux `ebpf`
   backend owns the complete descendant cgroup; reduced backends own only
   their documented frontend boundary.
3. Proxying, capture, and both TLS modes work without installing or starting a
   persistent Heimdall service.
4. Every run owns its relay, log directory, and policy state. The `ebpf`
   backend additionally owns isolated DNS listeners, cgroup, maps, and links;
   `interpose` owns a private injected library and authenticated frontend.
   Concurrent runs share no mutable data-plane state.
5. In `ebpf`, a narrowly authorized setup worker attaches eBPF, transfers owned FDs, and
   drops to the invoking user before the workload starts. It has no listener
   or machine-wide API.
6. The eBPF setup helper remains attached to the session as a parent-death guard.
   An unmarked owner exit kills the command cgroup before interception can
   disappear underneath surviving descendants.
7. Normal completion leaves no Heimdall process, listener, cgroup, BPF link,
   or map behind.

## Network contract

1. `ebpf` intercepts only the cgroup created for the wrapped command.
2. Policies select named SOCKS5 outbounds, direct egress, or explicit reject
   actions independently for TCP and UDP.
3. Fake DNS preserves hostnames for policy and upstream resolution; system DNS
   remains an explicit policy choice.
4. The eBPF boundary fails closed for unsupported or ambiguous network shapes.
   Reduced backends fail closed only for calls that enter their frontend and
   expose all known bypasses in the agent contract. A failed backend preflight
   never falls back to another backend.
5. `heimdall agent` reports concrete IPv4, IPv6, UDP, QUIC, runtime, and CLI
   acceptance evidence. A feature name alone is not a support claim.
6. For the selected policy, `decision.resolver` reports system DNS, direct
   port-53 interception, or a private resolver mount plus its NSS/nscd and
   user-namespace evidence. A deterministically disabled required namespace
   makes preflight not ready and withholds command execution argv.

## Capture and TLS contract

Proxying, payload retention, and plaintext inspection are independent choices:

- `decrypt.mode = "off"` proxies TLS as opaque transport.
- `decrypt.mode = "runtime"` observes supported OpenSSL APIs already
  mapped or discoverable through standard system loader paths during setup. It
  changes no trust. A loader-configured image may map after child exec because
  its inode-backed probes are pre-attached; private images outside those paths
  and other TLS libraries remain outside the claim.
- `decrypt.mode = "relay"` terminates TLS in the per-run relay using explicit
  invoking-user-owned CA material. Certificate pinning and client-certificate
  mTLS are outside this boundary. `tls init-ca` and `heimdall agent` expose the
  same public-certificate DER SHA-256 so command-scoped trust can be verified
  without exposing the signing key. Agent readiness also requires the same CA
  certificate/key, permissions, signing-usage, and key-match validation used by
  the runtime.
- `capture.mode = "on"` writes bounded private content-addressed blobs and
  `flow.data` references in `heimdall.event/v1`. The recorded boundary states
  whether bytes are opaque transport or observed plaintext.
- Capture boundary/direction allowlists run before payload retention. Exact
  values named by `capture.redact_env` are read from the inherited environment
  and masked before hashing or blob publication; unavailable values make the
  agent preflight not ready.
- When enabled plaintext capture contains a complete bounded HTTP/1 header,
  Heimdall may emit provenance-linked `http.request` or `http.response`
  metadata. Common credential headers are always masked and bodies remain only
  in the separately governed blob evidence.

Selecting a TLS mode is not proof that plaintext was observed. Agents must use
the reported capability and event boundary.

## Agent evidence contract

1. `heimdall agent` is read-only, emits exactly one `heimdall.agent/v10` JSON
   document, and represents executable actions as argv arrays.
   `actions.resolver_inspect` is a list of shell-safe argv arrays for the host
   files that produced `decision.resolver`; it never changes resolver or
   security state.
2. Each run writes one `heimdall.run/v1` manifest and ordered append-only
   `heimdall.event/v1` JSONL segments owned by the invoking user. Fake-DNS
   exchanges, policy decisions, flow boundaries, and TLS observations are
   explicit records rather than filename or port inferences. Derived HTTP/1
   records point back to the exact plaintext event sequences used to parse
   them.
3. JSONL files are the evidence source of truth. Strict
   `heimdall.logs.summary/v1` and `heimdall.logs.flow/v1` documents provide
   bounded read-only aggregation for a run or selected flow; they do not
   replace `logs verify` and never copy payload, derived headers, or SNI.
   `jq`, `rg`, `sed`, `sort`, `wc`, and the `heimdall logs` commands are
   supported analysis paths.
4. Heimdall owns active-file rotation and orphan recovery. Agents use `logs
   rotate`, `tail`, `query`, `verify`, `recover`, and `prune`; external rename
   and `copytruncate` are not safe for active segments.
5. Event, manifest, run-summary, and flow-summary schemas are bundled and
   available offline. The Heimdall skill documents
   field meanings, safe queries, rotation, integrity checks, and capability
   gates.

## Optional viewer

A future Web UI is optional, explicitly started, unprivileged, and read-only.
It reads the same manifests, JSONL segments, and referenced payload files
directly. It cannot enable TLS inspection, change policy, own capture, or
become required for a run. Starting, stopping, or restarting it cannot affect
the data plane.

## Platform scope

`execution.backend` is a required strict cross-platform enum containing
`ebpf`, `interpose`, and `explicit`. Heimdall never guesses or falls back. A
CLI `--backend` value may override the file for one command but may not change
backend on failure.

- `ebpf` is Linux-only and is the complete transparent command-cgroup
  boundary. It supports TCP/UDP policy, fake or system DNS, capture, runtime
  TLS, and relay TLS.
- `interpose` is a daemonless Linux and Apple-silicon backend for compatible
  dynamically linked TCP `connect` and libc `getaddrinfo` calls. Its embedded
  library authenticates to a private foreground SOCKS5 frontend with a fresh
  per-run secret. Common interposed IP-datagram send calls are rejected, but
  direct syscalls, alternate APIs, inherited sockets, loader-state removal,
  static code, and unsupported descendants remain bypasses. On macOS,
  SIP-protected and Hardened Runtime targets fail preflight; `connectx` and
  Network.framework are outside the hook set. Its source is
  `{backend:"interpose",scope:"interposed_dynamic_calls"}`. It requires UDP
  policy rejection, capture off, and decrypt off, and cannot claim transparent
  scope, complete descendant attribution, payload capture, TLS inspection,
  QUIC, or universal fail-closed behavior.
- `explicit` is a Linux and macOS x86_64/aarch64 CLI-only compatibility path for cooperative
  SOCKS-aware TCP clients. It owns a kernel-assigned loopback SOCKS5 CONNECT
  listener for one foreground run, evaluates shared TCP policy, sets only the
  child `ALL_PROXY` and `all_proxy`, and emits policy/flow metadata with
  `source={backend:"explicit",scope:"cooperative_environment"}`. It
  never changes system-wide proxy settings and cannot claim transparent UDP,
  fake DNS, QUIC, capture, TLS inspection, strict command scope, process
  attribution, or fail-closed coverage. It requires system DNS, rejected UDP,
  capture off, and decrypt off.
- `macos-transparent` is deferred source research that would require an
  optional signed companion containing an `NETransparentProxyProvider` system
  extension. The internal authenticated
  run-registration protocol has Rust and Swift implementations but remains
  unwired. An unsigned source prototype builds the app/system-extension bundle
  shape, refuses provider startup, closes unexpected flows, and cannot submit
  activation or save Network Extension configuration. It is not installable or
  routing support, is excluded from release artifacts, and reports
  `release_included=false`. If a future roadmap decision reactivates the path,
  optional flow metadata must pass signed native tests that
  distinguish registered, unrelated, missing, and ambiguous identity before
  this path may attribute a flow or release a command. If that discriminator
  is not safe, the backend does not ship. `NEAppProxyProvider` is reserved for
  a possible managed per-app deployment.

The current explicit and interpose backends use only
foreground-owned resources and no persistent user-managed Heimdall daemon.
Proxyman-style child-only proxy/trust adapters may be added for individually
tested runtimes, but Heimdall does not install Proxyman, mutate the system
proxy or keychain, or use PF/TUN as a product fallback. Runtime TLS is
unavailable on macOS. Official macOS release artifacts remain unavailable
until a versioned signed/notarized asset passes fresh-download install,
upgrade, rollback, uninstall, and reduced-backend acceptance. See
[design/macos-backend.md](design/macos-backend.md) and
[design/macos-fallbacks.md](design/macos-fallbacks.md).

## Acceptance rule

A capability is available only when its machine-readable contract, failure
behavior, documentation, and relevant unit or disposable real-eBPF VM path are
all present. Compilation alone is not acceptance.
