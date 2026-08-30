# macOS backend design

Status: **the reduced Apple-silicon explicit backend is available from source;
`macos-interpose` is implementation research; the Network Extension prototype
is deferred and excluded from releases; official macOS packages are not
available**.

This document records the implemented cooperative backend and fixes the
architecture boundaries for the daemonless fallback work and the retained
Network Extension prototype. Native explicit acceptance does not turn a proxy
environment into strict process scope, and a successful interpose probe,
cross-compile, or unsigned extension is never a transparent support claim. See
the [fallback research](macos-fallbacks.md) for the evaluated alternatives and
primary sources.

## Decisions

1. The `heimdall` CLI remains the only command users invoke.
   No persistent user-managed Heimdall daemon is installed or required.
2. A CLI-only explicit-proxy backend is a bounded compatibility mode. It is
   never selected silently and is not described as transparent or fail closed.
3. The active fallback research combines a proxychains-style
   `macos-interpose` library for compatible dynamic socket calls with
   Proxyman-style child-only runtime adapters. It never changes the system
   proxy or trust store and cannot claim universal process scope.
4. The checked-in `NETransparentProxyProvider` companion remains a deferred,
   source-only experiment. It is not built by the macOS release builder,
   packaged, signed, installed, activated, or promoted as the next backend.
5. `NEAppProxyProvider` is not the default command backend. Its manager is
   tied to managed per-app VPN configuration, so it remains a possible
   MDM-managed research path rather than a cgroup substitute.
6. A future macOS backend reuses the CLI-owned policy, relay, JSONL, capture,
   and relay-TLS boundaries. An interception component transports calls or
   flows; it does not become a policy or evidence authority.
7. macOS runtime TLS observation is unavailable. Relay TLS may become
   available only for explicitly supported runtime trust adapters after opaque
   TCP transport passes its own acceptance matrix.
8. Network Extension process attribution is a native evidence gate, not an API assumption.
   `sourceAppAuditToken` is optional, and Apple does not document it as a
   complete process-tree identity contract for every transparent flow. The
   deferred backend stays unavailable unless it is deliberately reactivated
   and signed native tests prove a safe discriminator for attributed,
   unrelated, missing, and ambiguous metadata.

## Three separate backends

| Backend | Installation | Intended coverage | Explicit limits |
| --- | --- | --- | --- |
| `macos-explicit` | Source-built `heimdall` CLI only; official package pending | Cooperative clients that honor a SOCKS proxy environment | Client-dependent TCP; no transparent UDP, fake DNS, QUIC, capture, TLS inspection, fail-closed, or strict command-scope claim |
| `macos-interpose` | Planned CLI plus signed interposition library | Compatible dynamically linked socket/resolver calls | In development and unselectable; SIP, Hardened Runtime, static code, alternate APIs, direct syscalls, and loader-state changes remain outside the claim |
| `macos-transparent` | Deferred source prototype; no release artifact | Possible operating-system flow interception if the path is reactivated | Requires paid entitlement, signed app/system extension, user approval, safe attribution, and coexistence acceptance |

`macos-explicit` does not modify machine-wide network settings. `heimdall
agent` prints an argv-safe execution prefix and the exact reduced capability
set. The run command rejects policies that need unavailable behavior before
exec. A client can ignore a proxy environment or open another socket path, so
this backend cannot promise that every connection is proxied or rejected.

## Implemented explicit architecture

```text
heimdall run --backend macos-explicit -- command
  |-- validates config and reduced backend capabilities
  |-- creates the private run store and JSONL owner
  |-- binds 127.0.0.1:<kernel-assigned> SOCKS5 CONNECT
  |     `-- shared TCP policy -> SOCKS5, direct, or reject
  `-- executes command with only:
        ALL_PROXY=socks5h://127.0.0.1:<port>
        all_proxy=socks5h://127.0.0.1:<port>
```

The foreground CLI removes inherited HTTP, HTTPS, FTP, ALL, and NO proxy
variables before adding those two values. It never exports configured upstream
credentials; they are resolved once inside Heimdall and used by the shared
SOCKS5 transport. The frontend accepts only unauthenticated loopback SOCKS5
CONNECT. UDP ASSOCIATE is rejected.

Shared TCP rules select `route`, `direct`, or `reject`. Preflight requires:

- Apple silicon;
- `dns.mode = "system"`;
- every UDP rule/final action to reject;
- `capture.mode = "off"`; and
- `decrypt.mode = "off"`.

The command must name `--backend macos-explicit`; there is no default or
implicit fallback. `heimdall agent` returns `ready=false`, stable diagnostics,
and no `actions.execute_prefix` when any condition is unmet or an outbound
credential cannot be read.

Policy decisions and TCP flow open/close records use:

```json
{"backend":"macos-explicit","scope":"cooperative_environment"}
```

This source field means the client reached the local listener. It does not
prove operating-system process attribution. No payload, DNS, TLS, or UDP event
is emitted. The foreground owner aborts listener tasks and closes the port
when the child exits. Child exit status is preserved, but the run manifest
sets `result.complete=false` and `descendants_cleaned=false` because a proxy
environment cannot prove or clean an entire descendant network scope.

Dynamic-loader interposition is now evaluated as the separately named
`macos-interpose` backend. Native feasibility proves an ordinary dynamic
target can load an injected library while a Hardened Runtime target and an
SIP-protected Apple binary do not. It cannot broaden the explicit contract or
inherit Linux claims. See [macOS fallback research](macos-fallbacks.md).

## Deferred Network Extension architecture

The following design is retained so the source prototype and its safety
invariants do not rot. It is not the active delivery sequence and is excluded
from release artifacts.

```text
heimdall run
  |-- validates config, creates run store and per-run relay
  |-- starts the command in a new, initially stopped process group
  |-- registers one authenticated run with the signed companion
  |     `-- Network Extension manager
  |           `-- NETransparentProxyProvider system extension
  |                 |-- proven unrelated flow -> return false / normal route
  |                 |-- proven attributed flow -> authenticated loopback channel
  |                                             `-- CLI-owned relay
  |                                                   |-- policy
  |                                                   |-- proxy/direct/reject
  |                                                   `-- JSONL/capture/TLS
  |                 `-- missing or ambiguous identity -> unresolved native gate
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

The internal [`heimdall.macos.control/v1`](macos-control-protocol.md) frame,
HMAC, strict sequence, registration validation, and in-memory lifecycle
registry are implemented and covered by portable tests. They are not connected
to a companion or provider. `heimdall run` cannot select this path, and
`heimdall agent` reports `provider_wired=false` and
`attribution.status=native_evidence_required`.

## Deferred compile-only companion prototype

The repository now contains the first non-routing Apple implementation slice:

- a Swift 6 `HeimdallMacControl` package that independently reproduces the
  Rust HMAC vector and strict envelope behavior;
- a macOS 11+ arm64 containing app with the system-extension install
  entitlement source and an `OSSystemExtensionRequest` factory;
- an embedded `NETransparentProxyProvider` system-extension target using
  Apple's `NetworkExtension` / `NEProviderClasses` bundle shape and the direct
  distribution `app-proxy-provider-systemextension` entitlement source; and
- `just test-macos-companion-native`, which performs Swift tests plus an
  unsigned Xcode Release build and verifies the `.app` / `.systemextension`
  product shape.

This slice is deliberately impossible to mistake for a working transparent
backend. The app never submits its activation request. No
`NETransparentProxyManager` is created and no preferences are saved. Provider
startup returns a stable prototype error. If a flow reaches the provider
despite that guard, the provider accepts and closes both directions instead of
returning `false` to the normal route. The build gate does not sign, install,
activate, approve, launch, or configure the extension.

The checked-in entitlement values document the intended direct-distribution
shape; they do not prove that Apple has authorized a profile or that an
installed signature contains those rights. `heimdall agent` therefore reports
the source prototype as `status="deferred"` and `release_included=false` while
keeping `signed=false`,
`installable=false`, `activation_enabled=false`,
`network_configuration_enabled=false`, and `provider_wired=false`.

## Command-scope contract

Network rules describe endpoints and protocol, not a process tree. The
transparent configuration therefore uses broad TCP/UDP rules only while runs
are active and classifies each new flow inside the provider.

For every run, registration contains at least:

- run ID, CLI owner PID, root command PID, and process-group ID;
- the expected executable path and process start epoch needed to reject PID
  reuse;
- the loopback relay endpoint and a random per-run authentication secret;
- policy/config digests and a bounded lease.

`NEFlowMetaData.sourceAppAuditToken` is one candidate input for deriving source
process identity, but the property is optional. Apple documents source
application metadata conservatively and does not promise a complete descendant
process graph for a transparent proxy. A signed prototype must measure its
presence and stability for direct children, grandchildren, exec, process-group
escape, PID reuse, TCP, UDP, and unrelated processes before any routing logic
depends on it.

This is not yet a process-group support claim. Returning a missing or ambiguous
flow direct could let the wrapped command bypass policy, while rejecting every
such flow could disrupt unrelated machine traffic. Heimdall therefore does not
guess between those outcomes. If native evidence cannot establish a safe
discriminator, the command-scoped transparent backend does not ship, or its
scope must be redesigned and named separately. The Linux phrase “complete
descendant cgroup” must not appear in macOS capability output.

## Lifecycle and failure behavior

1. The CLI completes config, log, relay, extension-presence, approval, and
   entitlement preflight before starting the command.
2. The command cannot execute network code until the provider acknowledges its
   registration and the selected attribution implementation has passed its
   native evidence gate.
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

The implemented protocol simulator proves registration is authenticated before
`run_ready`, strict request/response sequences reject replay, concurrent runs
do not stop the provider early, and owner-channel EOF removes the exact run.
It does not simulate Network Extension flow metadata and cannot satisfy the
native attribution gate.

Loopback and provider/control traffic are excluded from transparent diversion.
The CLI owner is outside the wrapped process group, so its upstream proxy and
direct sockets are not attributed to the command. Both conditions are required
to prevent relay recursion.

## TCP, UDP, DNS, QUIC, and TLS

| Capability | Deferred transparent milestone | Availability condition |
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

The current CLI-only package may expose only `macos-explicit`. The native
release builder does not build or include the companion, system extension, or
control transport. A future `macos-interpose` archive would add only a signed
and notarized library after its own acceptance matrix passes.

If the deferred path is ever reactivated, transparent support requires a
separately installed, notarized companion with the Network Extension
entitlement and a provisioning profile that authorizes the system-extension
form of the app-proxy provider capability. Direct distribution uses the
system-extension deployment shape; installation and first enablement may
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

The explicit source backend and its platform boundary are implemented:

- the crate selects separate Linux and Darwin roots while preserving the
  available Linux implementation unchanged;
- Linux-only aya, cgroup interception, original-destination correlation,
  capture, and TLS dependencies are excluded from the Darwin target;
- Darwin shares strict `init`, config schema, validation, and policy
  explanation behavior;
- one platform-neutral `RunEvidence` value owns the JSONL writer, rotation/event
  control sockets, and finalization order; the available Linux foreground path
  now uses that same owner;
- the Darwin CLI compiles the same event store and exposes `logs` schema,
  list, path, summary, flow, query, tail, rotate, verify, recovery, and retention
  commands for existing run data;
- one platform-neutral `relay_transport` module resolves outbound credentials
  and implements SOCKS5 TCP CONNECT, UDP ASSOCIATE, destination encoding,
  response validation, and setup timeouts; the available Linux relay now uses
  that implementation while retaining its Linux-only listeners and flow
  correlation; the explicit backend uses its TCP CONNECT path;
- `heimdall agent` reports `macos-explicit` available on Apple silicon,
  publishes its cooperative scope and exact limitations, and exposes an
  execution prefix only after config and credential preflight;
- `heimdall run` requires explicit backend selection, owns a loopback listener,
  emits cooperative TCP metadata, preserves child exit status, and closes all
  foreground resources; and
- `just check-macos` type-checks the CLI and portable protocol test targets for
  pinned `aarch64-apple-darwin` as part of `just verify`; native Apple-silicon
  `just test-macos-native` exercises `curl`, a fixture SOCKS5 upstream, JSONL
  integrity, listener cleanup, and pre-exec refusal; and
- the native release builder creates an arm64 macOS 11+ archive with normalized
  tar metadata and checksum. Its non-publishable ad-hoc gate covers Mach-O
  hygiene, install, simulated upgrade, rollback, and uninstall. Its official
  path requires Developer ID Application, Hardened Runtime, secure timestamp,
  warning-free notarization, and Gatekeeper assessment before returning an
  artifact to the Linux release transaction; and
- the internal `heimdall.macos.control/v1` protocol has strict framed JSON,
  HMAC-SHA256 authentication, direction and replay protection, validated
  per-run registration, concurrent-run registry transitions, and owner-EOF
  cleanup tests. The native Swift codec reproduces its fixed vector and strict
  framing; and
- the compile-only Xcode prototype produces one containing app with one
  embedded arm64 macOS 11+ system extension. Activation and Network Extension
  configuration are absent, provider startup fails closed, and unexpected
  flows are closed rather than returned to the normal route. It is deliberately
  not wired to a CLI backend or provider transport; and
- `just test-macos-interpose-feasibility` proves the current loader boundary
  without networking: an ordinary dynamic target loads the ad-hoc library,
  while Hardened Runtime and SIP-protected targets do not. No socket hook or
  backend is implemented yet.

No versioned official macOS archive or registry package has been published yet;
the package claim changes only after the signed/notarized path and a fresh
download acceptance complete for that release. The companion app, system
extension, transparent TCP/UDP, capture, and TLS paths remain unavailable for
installation or use; only their deferred unsigned source/build prototype
exists. `macos-interpose` is also unavailable and unselectable.

## Implementation sequence

1. Keep the completed target/dependency split, shared evidence owner, offline
   log tooling, outbound relay transport, and reduced machine contract covered.
2. Keep the implemented native package-mechanics gate green, then complete one
   Developer ID-signed/notarized versioned publication and fresh-download
   acceptance before declaring the archive available.
3. Keep the Rust/Swift protocol and provider skeleton green only through their
   explicit source gates. Do not invoke the native companion gate from package
   or release construction.
4. Build the proxychains-style `macos-interpose` fixture around authenticated
   constructor startup, TCP `connect`, libc resolver calls, and the existing
   foreground relay. Reject known incompatible targets before exec.
5. Add negative native tests for SIP, Hardened Runtime, static code, alternate
   networking APIs, direct syscalls, environment-cleared descendants, and
   unsupported spawn/exec shapes. Keep strict scope and UDP false.
6. Add Proxyman-style child-only runtime proxy/trust adapters without changing
   system proxy or keychain state. Add relay TLS only for individually accepted
   adapters; runtime TLS remains unavailable.
7. Package the interposition library only after signed/notarized fresh-archive
   acceptance. Keep the deferred companion out of that artifact.
8. Reconsider Network Extension work only through a future roadmap decision;
   reactivation still requires the complete signed attribution, coexistence,
   installation, approval, and cleanup matrix below.

## Native acceptance matrix

The explicit source gate is implemented as `just test-macos-native` on native
Apple silicon. It covers a cooperative `curl` request through a fixture SOCKS5
upstream, domain preservation, route evidence, JSONL verification, per-run
listener cleanup, normal and non-zero child exit propagation, and refusal to
execute when backend selection is omitted. It does not claim packaging or any
transparent capability.

`just test-macos-companion-native` is a separate unsigned source gate. It runs
the Swift codec conformance suite, builds the containing app and embedded
system extension with code signing disabled, checks both arm64 Mach-O binaries
and their macOS 11 deployment target, and validates the provider class and
bundle identifiers. It neither installs nor activates the result and supplies
no flow metadata, so it is not signed-provider or attribution evidence.

`just test-macos-interpose-feasibility` is a separate no-network research
gate. It proves only that the loader accepts an injected library for an
ordinary dynamic fixture and blocks it for Hardened Runtime and SIP-protected
targets. It is not part of package or release acceptance and does not prove a
socket hook, DNS, descendants, or fail-closed routing.

`just test-package-macos` adds a native package-mechanics matrix: pinned release
tests, the same explicit fixture, private/build-path and Mach-O checks, macOS
11.0 deployment target, normalized tar metadata, checksum, ad-hoc integrity
signature, atomic install, simulated upgrade, rollback, uninstall, and
unrelated-prefix preservation. Ad-hoc mode is deliberately impossible to use
from `scripts/publish-github-release`. The publish path independently requires
Developer ID, Hardened Runtime, timestamp, notarization result and log, and
Gatekeeper assessment. A successful mechanics gate is not a published-package
claim.

The deferred transparent matrix remains recorded below in case the roadmap
reactivates it. Compilation and simulator-style unit tests are insufficient;
availability would require a signed, entitled installation on native Apple
silicon covering:

- IPv4/IPv6 TCP and UDP, direct/proxy/reject policy, and unrelated-process
  non-interference;
- direct child, grandchild, exec, process-group escape, PID reuse, two
  concurrent runs, absent metadata, and ambiguous attribution;
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

Until the packaging gate passes, package pages and release notes must say that
official macOS packages are not available. Until an interpose or reactivated
transparent matrix passes, README, `heimdall agent`, package pages, and release
notes must keep every unimplemented macOS capability unavailable.

## Fallback references

- [macOS fallback research](macos-fallbacks.md)
- [proxychains-ng README](https://github.com/rofl0r/proxychains-ng/blob/master/README)
- [proxychains-ng interposition source](https://github.com/rofl0r/proxychains-ng/blob/master/src/libproxychains.c)
- [Apple Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)
- [Apple TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)
- [Proxyman proxy setting tool](https://docs.proxyman.com/basic-features/proxy-setting-tool)
- [Proxyman manual setup](https://docs.proxyman.com/automatic-setup/manual-setup)
- [mitmproxy macOS local capture](https://www.mitmproxy.org/posts/local-capture/macos/)

## Apple references

- [Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [`NETransparentProxyProvider`](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
- [`NETransparentProxyNetworkSettings`](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings)
- [`NEAppProxyProvider`](https://developer.apple.com/documentation/networkextension/neappproxyprovider)
- [`NEAppProxyProviderManager`](https://developer.apple.com/documentation/networkextension/neappproxyprovidermanager)
- [`NEFlowMetaData`](https://developer.apple.com/documentation/networkextension/neflowmetadata)
- [`NEFlowMetaData.sourceAppAuditToken`](https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappaudittoken)
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Installing system extensions and drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)
