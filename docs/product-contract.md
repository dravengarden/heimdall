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

1. Linux installation produces one `heimdall` executable. The eBPF object is
   embedded in that executable.
2. `heimdall run -- COMMAND` owns one foreground session for the complete
   descendant process tree.
3. Proxying, capture, and both TLS modes work without installing or starting a
   persistent Heimdall service.
4. Every run owns isolated relay and DNS listeners, cgroup, maps, links, log
   directory, and policy state. Concurrent runs share no mutable data-plane
   state.
5. A narrowly authorized setup worker attaches eBPF, transfers owned FDs, and
   drops to the invoking user before the workload starts. It has no listener
   or machine-wide API.
6. The setup helper remains attached to the session as a parent-death guard.
   An unmarked owner exit kills the command cgroup before interception can
   disappear underneath surviving descendants.
7. Normal completion leaves no Heimdall process, listener, cgroup, BPF link,
   or map behind.

## Network contract

1. Only the cgroup created for the wrapped command is intercepted.
2. Policies select named SOCKS5 outbounds, direct egress, or explicit reject
   actions independently for TCP and UDP.
3. Fake DNS preserves hostnames for policy and upstream resolution; system DNS
   remains an explicit policy choice.
4. Unsupported or ambiguous network shapes fail closed. Heimdall never falls
   back to unproxied egress because interception or relay setup failed.
5. `heimdall agent` reports concrete IPv4, IPv6, UDP, QUIC, runtime, and CLI
   acceptance evidence. A feature name alone is not a support claim.

## Capture and TLS contract

Proxying, payload retention, and plaintext inspection are independent choices:

- `decrypt.mode = "off"` proxies TLS as opaque transport.
- `decrypt.mode = "runtime"` observes supported OpenSSL APIs already
  discoverable at startup. It changes no trust and makes no claim for other TLS
  libraries or images loaded later.
- `decrypt.mode = "relay"` terminates TLS in the per-run relay using explicit
  invoking-user-owned CA material. Certificate pinning and client-certificate
  mTLS are outside this boundary.
- `capture.mode = "on"` writes bounded private content-addressed blobs and
  `flow.data` references in `heimdall.event/v1`. The recorded boundary states
  whether bytes are opaque transport or observed plaintext.
- Capture boundary/direction allowlists run before payload retention. Exact
  values named by `capture.redact_env` are read from the inherited environment
  and masked before hashing or blob publication; unavailable values make the
  agent preflight not ready.

Selecting a TLS mode is not proof that plaintext was observed. Agents must use
the reported capability and event boundary.

## Agent evidence contract

1. `heimdall agent` is read-only, emits exactly one `heimdall.agent/v8` JSON
   document, and represents executable actions as argv arrays.
2. Each run writes one `heimdall.run/v1` manifest and ordered append-only
   `heimdall.event/v1` JSONL segments owned by the invoking user. Fake-DNS
   exchanges, policy decisions, flow boundaries, and TLS observations are
   explicit records rather than filename or port inferences.
3. JSONL files are the evidence source of truth. `jq`, `rg`, `sed`, `sort`,
   `wc`, and the `heimdall logs` commands are supported analysis paths.
4. Heimdall owns active-file rotation. Agents use `logs rotate`, `tail`,
   `query`, `verify`, and `prune`; external rename and `copytruncate` are not
   safe for active segments.
5. Schemas are bundled and available offline. The Heimdall skill documents
   field meanings, safe queries, rotation, integrity checks, and capability
   gates.

## Optional viewer

A future Web UI is optional, explicitly started, unprivileged, and read-only.
It reads the same manifests, JSONL segments, and referenced payload files
directly. It cannot enable TLS inspection, change policy, own capture, or
become required for a run. Starting, stopping, or restarting it cannot affect
the data plane.

## Platform scope

The available backend is Linux cgroup v2 plus eBPF. macOS support remains a
roadmap item with separate capability contracts: a bounded wrapper fallback
and a signed `NETransparentProxyProvider` path. Neither may claim
Linux-equivalent command scope, UDP, DNS, QUIC, or TLS behavior without
platform-specific acceptance evidence.

## Acceptance rule

A capability is available only when its machine-readable contract, failure
behavior, documentation, and relevant unit or disposable real-eBPF VM path are
all present. Compilation alone is not acceptance.
