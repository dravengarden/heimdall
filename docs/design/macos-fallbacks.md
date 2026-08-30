# macOS fallback research

Status: **the daemonless fallback direction is selected for implementation
research; no new backend or official macOS package is available**.

This document records why Heimdall is exploring a proxychains-style dynamic
interposition backend and Proxyman-style per-runtime adapters instead of making
the Network Extension prototype the next release path. It is a design and
acceptance plan, not a support claim.

## Required product boundary

The primary macOS path must preserve these constraints:

- one foreground `heimdall run` owner and no persistent daemon;
- no machine-wide proxy, DNS, route, firewall, or trust-store mutation;
- no root requirement and no paid Apple Network Extension entitlement;
- explicit backend selection and machine-readable limitations;
- no request to disable System Integrity Protection or weaken code signing;
- no silent direct fallback when a selected interception mechanism fails; and
- TCP, UDP, DNS, process scope, capture, and TLS reported independently.

Those requirements deliberately trade universal application coverage for a
small installation and an honest command-line contract. A path that needs
global state or a separately approved application remains outside the default
CLI experience.

## Evaluated approaches

| Approach | What it actually covers | Decision |
| --- | --- | --- |
| Existing `macos-explicit` | Cooperative clients that honor a child-only SOCKS proxy environment | Keep available from source and extend with explicit runtime adapters; it remains bypassable and TCP-only |
| proxychains-style DYLD interposition | Socket and resolver calls made through an injected library in compatible dynamically linked processes | Main research candidate as separately named `macos-interpose`; no strict or universal scope claim |
| Proxyman system proxy/helper | Machine HTTP/HTTPS proxy configuration plus a privileged helper or app | Do not use as a Heimdall backend: it is global, protocol-specific, and can race with VPN software |
| Proxyman-style runtime setup | Per-command proxy and CA variables or native tool options | Adopt the adapter idea without requiring Proxyman, its GUI, helper, or global settings |
| mitmproxy local capture | Process-oriented capture implemented on macOS by a signed App Proxy Network Extension | Not an entitlement-free fallback; keep as a useful reference only |
| PF, TUN, or route manipulation | Host networking redirected with elevated global state | Do not use as the product backend: it is not naturally command-scoped, conflicts with other network software, and PF is not a supported macOS product API |
| `NETransparentProxyProvider` / `NEAppProxyProvider` | Operating-system flow interception through an entitled, signed, approved app or system extension | Retain the fail-closed source prototype as deferred research; exclude it from release artifacts and the active delivery plan |

The useful combination is therefore not “embed Proxyman.” It is:

1. use the existing foreground SOCKS listener for clients that expose proxy
   controls;
2. add built-in, inspectable adapters for common CLI runtimes where generic
   proxy or CA variables are insufficient; and
3. use a bundled interposition library to reach compatible programs that call
   the normal Darwin socket and resolver surface.

## Native feasibility evidence

On 2026-08-30, an Apple-silicon host running macOS 26.4.1 produced this bounded
result with an ad-hoc-signed constructor probe:

| Target | Injected library loaded |
| --- | --- |
| Ordinary ad-hoc-signed dynamic executable | Yes |
| The same executable signed with Hardened Runtime | No |
| SIP-protected `/usr/bin/true` | No |

`just test-macos-interpose-feasibility` reproduces that boundary without
opening a socket or changing system state. It proves only loader behavior. It
does not prove `connect` routing, DNS handling, descendants, or fail-closed
coverage.

The result matches the documented limits of both proxychains-ng and Apple's
Hardened Runtime. Interposition is viable for a useful subset of development
tools, but the subset must be detected and named; it cannot be described as a
transparent macOS equivalent to Linux cgroup eBPF.

## Candidate `macos-interpose` architecture

```text
heimdall run --backend macos-interpose -- command
  |-- inspect the root Mach-O and selected policy
  |-- bind the foreground relay, control channel, and JSONL owner
  |-- inject a signed libheimdall_interpose.dylib into a compatible target
  |     |-- constructor authenticates to the run before application main
  |     |-- connect -> route / direct / reject through the CLI-owned relay
  |     |-- resolver calls -> preserve a hostname for proxy-side DNS
  |     `-- exec/spawn hooks -> inspect or reject unsupported descendants
  `-- close the relay, library session, and logs when the foreground run ends
```

The first implementation slice is TCP only. Ordinary UDP, QUIC, raw DNS, a
static binary, a SIP-protected executable, a Hardened Runtime target that
rejects the library, alternate networking APIs, direct syscalls, and children
that clear loader state are unavailable until separately proven. Hooking
`sendto` only for TCP Fast Open does not constitute UDP support.

The library must reject a network call if its authenticated foreground relay
is unavailable. The CLI must reject targets it can identify as incompatible
before exec. Even with both checks, absence of an operating-system enforcement
boundary means the backend cannot claim universal fail-closed process-tree
coverage. Its machine contract will say `scope=interposed_dynamic_calls`,
`strict_command_scope=false`, and `client_can_bypass=true` unless native
negative tests establish a stronger, precisely bounded statement.

No interposition backend is silently selected. `macos-explicit` remains a
separate cooperative mode, and a failed `macos-interpose` preflight does not
retry through the normal network or another backend.

## DNS and TLS

Resolver hooks can pass a domain name to the existing SOCKS5 transport, which
is preferable to creating a host-wide resolver or fake-IP range. The first
milestone must cover `getaddrinfo` and related libc resolver calls while
reporting raw DNS sockets, encrypted DNS, cached answers, and alternate
resolver APIs as unavailable.

Interposition changes transport, not TLS trust. Opaque TLS can cross the relay
without modifying the client. Relay TLS inspection may be added only through
an explicit adapter matrix that sets child-only trust inputs or argv for a
known runtime, such as OpenSSL-style CA variables or a runtime's dedicated CA
option. It must not install a root certificate into the system keychain.
Certificate pinning and client-certificate mTLS remain unsupported.

Adapters are built-in implementation knowledge, not a new workload policy
language. `heimdall agent` must expose the selected adapter, exact environment
or argv additions, and its tested runtime/version boundary before offering an
execution prefix.

## Implementation and acceptance order

1. Keep `macos-explicit` and its native acceptance unchanged.
2. Keep the Network Extension code buildable through its explicitly invoked
   source-only gate, but do not build or package it from the macOS release
   asset path.
3. Land a standalone interposition fixture for constructor authentication,
   `connect`, hostname preservation, relay loss, and a non-networking target.
4. Add root-target preflight for Mach-O architecture, dynamic loading,
   Hardened Runtime, SIP/restricted code, and library-validation boundaries.
5. Add negative acceptance for static, protected, hardened, environment-cleared,
   alternate-API, direct-syscall, and unsupported descendant cases before
   exposing a selectable backend.
6. Add `exec`/`posix_spawn` coverage and report exactly which descendants keep
   the library. Do not use “complete process tree” until escape tests pass.
7. Add common CLI proxy/trust adapters and relay TLS only after each adapter
   has native positive and negative tests.
8. Package the signed/notarized CLI and interposition library only after a
   fresh archive passes signature, Gatekeeper, install, upgrade, rollback,
   uninstall, and backend acceptance. The deferred companion is not part of
   that archive.

The Network Extension design may be reconsidered later if entitlement,
installation, approval, coexistence, and attribution costs become acceptable.
Reactivation is a roadmap decision, not an automatic continuation of the
checked-in prototype.

## Primary references

- [proxychains-ng README](https://github.com/rofl0r/proxychains-ng/blob/master/README) — preloaded-library mechanism, macOS support, TCP-only boundary, and compatibility warnings
- [proxychains-ng interposition source](https://github.com/rofl0r/proxychains-ng/blob/master/src/libproxychains.c) — Darwin interpose declarations and the hooked socket/resolver surface
- [Apple Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime) — code-injection and library-validation boundary
- [Apple TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) — why PF is not a supported product integration
- [Proxyman proxy setting tool](https://docs.proxyman.com/basic-features/proxy-setting-tool) and [manual setup](https://docs.proxyman.com/automatic-setup/manual-setup) — system-proxy/helper and runtime-specific setup boundaries
- [Proxyman command line](https://docs.proxyman.com/command-line) — CLI control of the installed application rather than a standalone command interceptor
- [mitmproxy proxy modes](https://docs.mitmproxy.org/stable/concepts/modes/) and [macOS local-capture implementation](https://www.mitmproxy.org/posts/local-capture/macos/) — process selection implemented through a Network Extension
