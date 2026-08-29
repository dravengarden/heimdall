# macOS backend design

Status: **in development; no macOS backend is available in a release yet**.

This document fixes the product and architecture boundaries for macOS before
implementation. It does not turn a successful cross-compile, an unsigned
extension, or a cooperative proxy environment into a support claim.

## Decisions

1. The `heimdall` CLI remains the only command users invoke.
   No persistent user-managed Heimdall daemon is installed or required.
2. A CLI-only explicit-proxy backend is a bounded compatibility mode. It is
   never selected silently and is not described as transparent or fail closed.
3. Transparent TCP and UDP use an optional signed companion containing an
   `NETransparentProxyProvider` system extension. The extension is enabled
   only while at least one transparent run is active.
4. `NEAppProxyProvider` is not the default command backend. Its manager is
   tied to managed per-app VPN configuration, so it remains a future option
   for MDM-managed deployments rather than a cgroup substitute.
5. The transparent backend reuses the CLI-owned policy, relay, JSONL, capture,
   and relay-TLS boundaries. The provider classifies and transports flows; it
   does not become a policy or evidence authority.
6. macOS runtime TLS observation is unavailable. Relay TLS may become
   available only after transparent flow forwarding and explicit trust pass
   their own acceptance matrix.

## Two separate backends

| Backend | Installation | Intended coverage | Explicit limits |
| --- | --- | --- | --- |
| `macos-explicit` | `heimdall` CLI only | Cooperative clients that honor an explicit SOCKS or proxy environment | Client-dependent TCP; no transparent UDP, fake DNS, QUIC, runtime TLS, or strict command-scope claim |
| `macos-transparent` | `heimdall` plus signed companion/system extension | Transparently attributed TCP and UDP flows from the wrapped process group | Not Linux cgroup-equivalent until descendant attribution, escape behavior, and race handling pass native acceptance |

`macos-explicit` must not modify machine-wide network settings. The CLI prints
the exact environment or wrapper mechanism it selected, records the reduced
capability set, and rejects policies that need unavailable behavior. A client
can ignore a proxy environment or open another socket path, so this backend
cannot promise that every connection is proxied or rejected.

Dynamic-loader interposition may be evaluated as a separately named explicit
backend, but it cannot broaden this contract. System Integrity Protection,
hardened runtimes, static code, alternate socket APIs, and child environment
changes make interposition incomplete by design.

## Transparent architecture

```text
heimdall run
  |-- validates config, creates run store and per-run relay
  |-- starts the command in a new, initially stopped process group
  |-- registers one authenticated run with the signed companion
  |     `-- Network Extension manager
  |           `-- NETransparentProxyProvider system extension
  |                 |-- unrelated flow -> return false / normal route
  |                 `-- attributed flow -> authenticated loopback channel
  |                                             `-- CLI-owned relay
  |                                                   |-- policy
  |                                                   |-- proxy/direct/reject
  |                                                   `-- JSONL/capture/TLS
  `-- releases the command only after registration is acknowledged
```

The containing app exists to install, approve, and manage the system
extension. It is not a required dashboard. The operating system owns the
provider process lifecycle. While a transparent run is active, Heimdall must
report the provider and session helper as active components rather than calling
the path process-free.

The session helper is foreground-run-owned. It watches the CLI owner, forwards
registration messages, and unregisters the run on normal exit or owner death.
It has no machine-wide API and does not survive the last active run. Concurrent
runs coordinate through a locked, user-owned registration store; the final
unregister operation disables the transparent configuration after the provider
confirms that no sessions remain.

## Command-scope contract

Network rules describe endpoints and protocol, not a process tree. The
transparent configuration therefore uses broad TCP/UDP rules only while runs
are active and classifies each new flow inside the provider.

For every run, registration contains at least:

- run ID, CLI owner PID, root command PID, and process-group ID;
- the expected executable identity and creation epoch needed to reject PID
  reuse;
- the loopback relay endpoint and a random per-run authentication secret;
- policy/config digests, registration expiry, and heartbeat state.

The provider reads `NEFlowMetaData.sourceAppAuditToken`, derives the source
process identity, and checks it against the registered root/process group and
its observed parent chain. An unrelated flow is returned to the normal network
path. A flow attributed to a registered run is never returned direct because
the relay is unavailable.

This is initially a **process-group best-effort** scope. A descendant that
creates a new session or process group is outside the support claim until
native tests prove a safe attribution rule. Ambiguous overlap between two run
registrations is rejected instead of guessed. The Linux phrase “complete
descendant cgroup” must not appear in macOS capability output.

## Lifecycle and failure behavior

1. The CLI completes config, log, relay, extension-presence, approval, and
   entitlement preflight before starting the command.
2. The command cannot execute network code until the provider acknowledges its
   registration.
3. Registration failure terminates the stopped child and finalizes a failed
   run; it never retries through the explicit backend unless the user selected
   that backend.
4. Provider loss, relay authentication failure, relay loss, or an expired
   heartbeat closes every flow already attributed to that run.
5. Owner death makes the session helper terminate the registered process group,
   unregister it, and retain a short tombstone so late flows cannot escape.
6. Normal completion unregisters the run, finalizes JSONL, removes its relay,
   and disables the provider after the last active run.
7. Stale registration recovery is explicit, evidence-producing, and bounded;
   it may not silently trust a reused PID.

Loopback and provider/control traffic are excluded from transparent diversion.
The CLI owner is outside the wrapped process group, so its upstream proxy and
direct sockets are not attributed to the command. Both conditions are required
to prevent relay recursion.

## TCP, UDP, DNS, QUIC, and TLS

| Capability | First transparent milestone | Availability condition |
| --- | --- | --- |
| TCP | Forward attributed IPv4/IPv6 streams to the per-run relay | unrelated-process, relay-loss, half-close, backpressure, and long-lived-stream tests pass |
| UDP | Preserve datagram boundaries and destination metadata | connected/unconnected UDP, timeout, truncation, and concurrent-flow tests pass |
| DNS | Record hostname metadata when the flow API supplies it; otherwise treat DNS as UDP/TCP evidence | resolver-specific tests prove attribution and no host-wide resolver mutation |
| Fake DNS | unavailable initially | a macOS-specific resolver design and collision/recovery matrix exist |
| QUIC | unavailable initially | UDP plus migration, rebinding, and policy-correlation tests pass |
| Runtime TLS | unavailable | no design currently claims library-level observation on macOS |
| Relay TLS | later transparent milestone | raw TCP relay, trust installation, SNI/ALPN, pinning, mTLS, and failure evidence pass native tests |

`NETransparentProxyNetworkSettings` does not apply DNS or ordinary proxy
settings. Connect-by-name flows may retain hostname context, but that does not
prove coverage for raw DNS sockets, encrypted DNS, cached answers, or every
resolver API. Capability output and JSONL must identify what was actually
observed.

## Packaging and authorization

The CLI-only package may expose only `macos-explicit`. Transparent support
requires a separately installed, notarized companion with the Network
Extension entitlement and a provisioning profile that authorizes the system
extension form of the app-proxy provider capability. Direct distribution uses
the system-extension deployment shape; installation and first enablement may
require user approval.

`heimdall agent` must distinguish at least:

- operating-system and CPU compatibility;
- companion installed, code signature valid, and expected team/bundle identity;
- extension entitlement/profile present;
- extension approved and configuration loadable;
- selected backend and its exact TCP/UDP/DNS/QUIC/TLS/scope capability set;
- blocking diagnostics with argv-safe, non-destructive inspection actions.

No setup instruction may ask a user to disable System Integrity Protection,
weaken signature validation, or install a permanent host-wide proxy.

## Current implementation status

The compile boundary and first evidence-ownership extraction are implemented:

- the crate selects separate Linux and Darwin roots while preserving the
  available Linux implementation unchanged;
- Linux-only aya, cgroup, relay, capture, and TLS dependencies are excluded
  from the Darwin target;
- Darwin shares strict `init`, config schema, validation, and policy
  explanation behavior;
- one platform-neutral `RunEvidence` value owns the JSONL writer, rotation/event
  control sockets, and finalization order; the available Linux foreground path
  now uses that same owner;
- the Darwin scaffold compiles the same event store and exposes `logs` schema,
  list, path, summary, flow, query, tail, rotate, verify, recovery, and retention
  commands for existing run data;
- `heimdall agent` validates that shared config but reports both backends as
  unavailable, leaves `execution` and `actions.execute_prefix` null, exposes
  argv-safe offline log actions, and exits 1;
- `heimdall run` exits 1 without executing the supplied command; and
- `just check-macos` type-checks the CLI for pinned
  `aarch64-apple-darwin` as part of `just verify`.

This is build scaffolding, not a macOS package or transport implementation.
The Darwin log commands can inspect a compatible existing store, but no macOS
backend creates traffic events yet. No explicit proxy, companion app, system
extension, TCP/UDP forwarding, capture, or TLS path is available.

## Implementation sequence

1. Keep the completed target/dependency split, shared evidence owner, offline
   log tooling, and unavailable machine contract covered while extracting the
   platform-neutral relay transport.
2. Implement and accept `macos-explicit` as an opt-in reduced mode.
3. Add the signed containing app, system extension, minimal session helper, and
   versioned authenticated registration protocol.
4. Accept transparent TCP and process attribution before adding UDP.
5. Add UDP, then DNS and QUIC only as separately reported capabilities.
6. Reuse relay TLS and capture only after opaque transparent transport is
   stable. Runtime TLS remains unavailable.
7. Add notarized release artifacts only after clean-machine installation,
   approval, upgrade, rollback, uninstall, and fresh-run acceptance pass.

## Native acceptance matrix

Compilation and simulator-style unit tests are necessary but insufficient.
Availability requires a signed, entitled installation on native Apple silicon
covering:

- IPv4/IPv6 TCP and UDP, direct/proxy/reject policy, and unrelated-process
  non-interference;
- direct child, grandchild, exec, process-group escape, PID reuse, two
  concurrent runs, and ambiguous attribution;
- pre-exec registration failure, provider crash/restart, CLI kill -9, relay
  loss, sleep/wake, network change, and reboot recovery;
- DNS APIs, raw port 53, cached answers, encrypted DNS boundaries, and no
  machine-wide resolver mutation;
- relay recursion protection, backpressure, long-lived flows, UDP expiry, and
  QUIC only when claimed;
- opaque TLS first, then relay TLS trust and evidence boundaries;
- append-only JSONL integrity, rotation, orphan recovery, and complete cleanup;
- companion install, approval, upgrade, rollback, uninstall, and no enabled
  extension after the final run.

Until this matrix passes, README, package pages, `heimdall agent`, and release
notes must say that macOS is not available.

## Apple references

- [Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [`NETransparentProxyProvider`](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
- [`NETransparentProxyNetworkSettings`](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings)
- [`NEAppProxyProvider`](https://developer.apple.com/documentation/networkextension/neappproxyprovider)
- [`NEAppProxyProviderManager`](https://developer.apple.com/documentation/networkextension/neappproxyprovidermanager)
- [`NEFlowMetaData.sourceAppAuditToken`](https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappaudittoken)
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
