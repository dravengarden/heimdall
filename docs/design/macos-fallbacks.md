# macOS fallback decision

Heimdall keeps the entitled Network Extension prototype deferred and ships two
daemonless CLI boundaries instead: `interpose` for compatible dynamic calls and
`explicit` for cooperative SOCKS-aware clients. Linux may also select
`interpose` when no-privilege operation matters more than complete cgroup
coverage.

## What was evaluated

| Strategy | What it can cover | Product decision |
| --- | --- | --- |
| Child proxy environment | Clients that honor SOCKS environment variables | Implemented as `explicit`; simple and bypassable |
| proxychains-style loader interposition | Compatible dynamically linked socket and resolver calls | Implemented as `interpose`; precise reduced scope, no transparent claim |
| Proxyman-style runtime adapters | Individually supported tools with proxy and trust controls | Optional future compatibility work, one native-tested runtime at a time |
| mitmproxy local capture | Explicit proxy-aware clients | Not a transparent fallback; Heimdall already owns the foreground relay |
| PF redirection | Broad socket redirection | Rejected as a CLI default because DNS, attribution, cleanup, privilege, and VPN coexistence are poor boundaries |
| TUN/VPN | Broad IP traffic | Rejected as a lightweight command wrapper; machine-wide coordination and conflicts exceed the product scope |
| `NETransparentProxyProvider` | OS-mediated TCP/UDP flows | Deferred; requires entitled signed companion, installation, approval, and reliable command attribution |
| `NEAppProxyProvider` | Managed per-app traffic | Deferred research for managed deployments, not arbitrary child processes |

## Why interposition is deliberately partial

Loader interposition is useful because it needs no root, daemon, VPN slot,
system proxy mutation, or Network Extension entitlement. It cannot define a
kernel-enforced process boundary:

- SIP-protected executables may discard DYLD variables;
- Hardened Runtime library validation may reject injected code;
- static binaries and direct syscalls do not call the hooked symbols;
- `connectx`, Network.framework, language-specific resolvers, and inherited
  sockets can avoid `connect`/`getaddrinfo`;
- descendants can clear loader state;
- alternate or direct UDP paths remain outside the common rejected hook set.

The product therefore names its scope `interposed_dynamic_calls`, sets
`strict_command_scope=false` and `client_can_bypass=true`, and writes the same
boundary into every policy/flow event. A successful request never upgrades
that claim.

## Implemented runtime

```text
config execution.backend=interpose
        |
        +-- preflight config, native artifact, target, and loader state
        +-- start authenticated per-run SOCKS5 TCP frontend
        +-- materialize embedded .so/.dylib privately
        +-- inject child-only loader variables
        +-- route interposed connect/getaddrinfo through shared policy
        +-- reject common interposed IP-datagram sends
        `-- finalize JSONL and delete all per-run runtime state
```

Linux uses `LD_PRELOAD`; macOS uses `DYLD_INSERT_LIBRARIES`. Both use the same
strict config, relay transport, policy evaluation, authentication, event
source, and teardown. The native library never receives upstream credentials;
it knows only the loopback port, one-time secret, and fake-DNS mode.

`explicit` remains separate. It sets `ALL_PROXY`/`all_proxy`, requires system
DNS, and uses `scope=cooperative_environment`. A failed interpose preflight
does not fall back to explicit or eBPF.

## Validation model

Product acceptance proves:

- config-only and one-run backend selection;
- Agent v10 reports exact scope, failure boundary, and bypasses;
- real authenticated TCP routing and original-host preservation;
- rejected common connected and connectionless UDP calls;
- policy/flow metadata source and offline integrity;
- exit-code propagation and private-library/listener cleanup;
- platform preflight rejects unsupported targets before exec.

The separate Apple-silicon boundary fixture continues to inventory positive
dynamic hooks and negative paths such as loader removal, alternate APIs,
protected targets, and descendants. It is evidence for limitations, not a
second backend.

## Remaining work

- Add compatibility fixtures for real CLI/runtime clients one at a time.
- Evaluate child-only CA/proxy adapters only when they avoid system keychain or
  proxy mutation and have positive and negative native tests.
- Expand UDP rejection hooks only as a safety improvement; do not call it UDP
  proxying or strict fail-closed scope.
- Publish macOS only after Developer ID signing, notarization, Gatekeeper, and
  fresh-download package acceptance pass for the versioned artifact.
- Keep the Network Extension source excluded unless a future roadmap decision
  explicitly reopens entitlement, installation, coexistence, and attribution
  work.
