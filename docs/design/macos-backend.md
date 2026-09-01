# macOS backend

Status: `explicit` is architecture-neutral and supported on x86_64 and
Apple-silicon macOS; its Darwin compile gate covers both and its native gate is
portable across them. `interpose` is implemented and native-accepted on Apple
silicon. Neither is a transparent command-tree boundary. The Network Extension
prototype is deferred source research and excluded from every package and release.

## Select the boundary in config

macOS never guesses a reduced backend:

```toml
[execution]
backend = "explicit" # Apple silicon may instead select "interpose".
```

`ebpf` fails before the command executes. `--backend` can override
the file for one run, but automation should call `heimdall agent` and append its
command argv to the returned `actions.execute_prefix`.

| Backend | Available | Boundary | Privilege |
| --- | --- | --- | --- |
| `interpose` | Apple silicon and Linux | Compatible dynamic TCP `connect` and libc `getaddrinfo` calls | None |
| `explicit` | macOS x86_64/aarch64 and Linux | Cooperative clients that honor a child SOCKS proxy environment | None |
| `macos-transparent` | No; deferred source only | Proposed Network Extension process flow | Entitled companion would be required |

Both released paths are foreground-only. They start no daemon or Web UI,
change no system proxy setting, install no certificate, and leave no listener
or injected library after the run exits.

## Interpose

```text
heimdall run --backend interpose -- command
        |
        +-- private run store + JSONL writer
        +-- authenticated 127.0.0.1:<kernel-assigned> SOCKS5 listener
        |       `-- shared TCP policy -> SOCKS5, direct, or reject
        +-- embedded dylib materialized beside the private event socket
        `-- DYLD_INSERT_LIBRARIES for the child
                +-- connect -> authenticated listener
                `-- getaddrinfo -> per-run synthetic address -> original host
```

The library is compiled into the single `heimdall` binary. One run writes it
with private permissions, verifies its code signature, creates a fresh
authentication secret, injects only the child environment, and removes the
file at teardown. It strips inherited proxy and Heimdall loader variables and
rejects a pre-existing loader injection instead of composing unknown hooks.

The listener accepts only SOCKS5 TCP CONNECT with RFC 1929 authentication. It
evaluates the same ordered route/direct/reject policy and uses the same
outbound transport as Linux. Interposed libc hostname resolution may return a
synthetic address so a later interposed `connect` preserves the original
domain. This is not raw DNS, port-53, or alternate-resolver interception.

Preflight requires:

- `execution.backend = "interpose"` or an explicit one-run override;
- every UDP policy path rejects;
- `capture.mode = "off"` and `decrypt.mode = "off"`;
- every referenced TCP route uses a TCP-capable readable outbound;
- a dynamically linked, non-SIP-protected target without Hardened Runtime
  library validation that would discard or reject injection;
- no existing `DYLD_INSERT_LIBRARIES` or `DYLD_FORCE_FLAT_NAMESPACE` state.

Common interposed IP-datagram `connect`, `send`, `sendto`, and `sendmsg` calls
return `EACCES`. That prevents an ordinary client from accidentally using UDP
inside the supported hook set; it does not create transparent UDP coverage.

The machine-readable boundary is:

```json
{
  "backend": "interpose",
  "scope": "interposed_dynamic_calls",
  "failure_boundary": "interposed_calls_only",
  "strict_command_scope": false,
  "client_can_bypass": true
}
```

Known bypasses include static code, direct syscalls, inherited sockets,
alternate socket or resolver APIs, `connectx`, Network.framework, loader-state
removal, uninterposed UDP calls, and descendants that discard loader state.
SIP-protected and detected Hardened Runtime targets fail preflight, but
preflight cannot prove the behavior of every future descendant. Therefore a
normal run manifest remains incomplete as a whole-process attribution claim.

Policy and flow events use:

```json
{"backend":"interpose","scope":"interposed_dynamic_calls"}
```

That source proves that a connection authenticated through the injected
frontend. It does not prove that every socket opened by the process tree did
so. Payload, TLS, and process-attribution evidence are unavailable.

## Explicit

```text
heimdall run --backend explicit -- command
        |
        +-- private run store + JSONL writer
        +-- 127.0.0.1:<kernel-assigned> SOCKS5 CONNECT listener
        |       `-- shared TCP policy -> SOCKS5, direct, or reject
        `-- child ALL_PROXY/all_proxy=socks5h://127.0.0.1:<port>
```

This backend removes inherited proxy variables and supplies only `ALL_PROXY`
and `all_proxy`. A compatible client such as curl can use the listener; a
client may ignore or replace those variables. Preflight requires system DNS,
rejected UDP, capture off, decrypt off, and TCP-capable outbounds.

Events use:

```json
{"backend":"explicit","scope":"cooperative_environment"}
```

This proves only that the client reached the cooperative listener. It is not
process identity, descendant attribution, fake DNS, UDP, payload capture, TLS
inspection, or fail-closed coverage.

## Deferred Network Extension path

The repository retains an internal `heimdall.macos.control/v1` Rust/Swift
codec and a compile-only containing app plus `NETransparentProxyProvider`
system-extension skeleton. The provider refuses startup, closes unexpected
flows, cannot submit activation, and saves no Network Extension configuration.
Package and release construction must not build or include it.

This path stays deferred because it would require an Apple Developer Program
team, restricted entitlements, signed installation and user approval, and
native proof that flow metadata safely distinguishes the requested command
from unrelated traffic. `NEAppProxyProvider` remains a possible managed-app
research option, not a CLI fallback.

## Packaging boundary

Native source acceptance uses an ad-hoc signature. A publishable archive must
use a configured Developer ID Application identity for both the embedded dylib
and CLI, enable the release signing policy, notarize and staple the archive,
pass Gatekeeper, and then pass fresh-download install, run, upgrade, rollback,
and uninstall acceptance. Until that transaction succeeds for a versioned
asset, documentation must distinguish native source support from an official
macOS release.

The package contains one CLI. The dylib remains embedded bytes until a selected
interpose run materializes it; there is no companion, launch agent, daemon, or
persistent privileged installation.

## Acceptance

```bash
# Both Darwin architectures from the pinned Linux development shell
nix develop -c just check-macos

# Native explicit gate on either macOS architecture
just test-macos-explicit-native

# Native Apple-silicon combined/interpose gates
just test-macos-native
just test-macos-interpose-native

# Deferred source-only prototype
just test-macos-companion-native
```

`test-macos-explicit-native` accepts `explicit` on the current native macOS
architecture. `test-macos-native` runs both `explicit` and `interpose`
acceptance on Apple silicon. Interpose
acceptance covers config-only selection, Agent v10, authenticated real relay
routing, domain preservation, common UDP-call rejection, JSONL integrity,
private-library cleanup, exit status, and SIP preflight rejection. The separate
boundary fixture inventories unsupported APIs so new work cannot silently
broaden the claim.
