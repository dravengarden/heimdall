# Architecture

Heimdall has one product path: wrap a command and proxy that command's
outbound connections.

```text
heimdall run -- command
        |
        | create transient cgroup and register policy choice
        v
privileged heimdall daemon
        |  eBPF redirects only the registered cgroup
        |  fake-IP DNS preserves hostnames
        v
named SOCKS5 proxy
        |
        v
destination
```

## Boundaries

The CLI is the product surface. It selects a named policy, creates a child
cgroup, executes the command, forwards its exit status, and cleans up.

The daemon is implementation infrastructure. It loads the eBPF object,
maintains a local cgroup-to-policy registry, runs the TCP/UDP relay and fake-IP
DNS, and reaps abandoned CLI cgroups. Its default eBPF policy is always bypass, so
an unregistered process cannot be redirected accidentally.

The internal relay binds fixed IPv4 and IPv6 loopback sockets on port 12345;
fake DNS binds both loopback families over UDP and TCP before readiness. These
data-plane endpoints cannot be exposed or made inconsistent with eBPF by
configuration.

The configuration contains named outbounds and command-selected policies with
ordered destination rules. It has no workload selector language or
orchestrator-shaped metadata.

## Connection lifecycle

1. `heimdall run` re-enters through `systemd-run --user --scope` when needed.
2. It creates an `heimdall-cli-*` cgroup below the delegated user subtree.
3. It registers that cgroup ID and policy name with the local daemon.
4. The child joins the cgroup and executes the requested command.
5. eBPF rewrites the child's TCP and UDP destinations to the local relay. IPv4
   connectionless sends receive a stable per-socket-and-destination token;
   connectionless IPv6 is rejected fail-closed. DNS traffic is redirected over
   UDP or TCP when the policy uses fake DNS. System DNS is explicitly allowed
   to port 53.
6. The relay recovers the original destination, evaluates the policy's ordered
   protocol rules, and routes, connects directly, or rejects it. Connected UDP
   reuses one bidirectional upstream association per socket. IPv4 connectionless
   UDP reuses one association per socket and destination.
7. Application bytes, including TLS records, pass through unchanged. Heimdall
   never uses SNI to reinterpret an IP destination: fake DNS produces a SOCKS5
   domain request, while system DNS preserves the resolved IP address.
8. The parent forwards the child's exit status and deregisters the cgroup.

If the parent is killed, the daemon's bounded cgroup scan removes the orphan
after it becomes empty.

Fake-IP mappings remain stable for the daemon lifetime. A depleted pool returns
DNS `SERVFAIL` instead of reassigning an address that an application may still
hold in its cache.

TCP and connected IPv6 relay keys include both address family and ephemeral
source port. IPv4 UDP instead rewrites each socket-and-destination flow to a
distinct address in `127/8`; `recvmsg4` restores the real source address on the
return path. This avoids ambiguity for an unconnected socket targeting several
peers and for concurrent `SO_REUSEPORT` sockets. Connected IPv6 keeps the
family-and-port path; simultaneous IPv6 sockets sharing one source port remain
unsupported. The daemon verifies socket liveness before returning every
upstream datagram and closes the session when the socket disappears, its CLI
cgroup deregisters, orphan GC runs, or the session remains idle for 60 seconds.

## Non-goals

- cluster or container orchestration integration
- host-wide routing rules for services
- workload labels, annotations, or admission hooks
- a Web UI or public HTTP API as a primary interface
- TLS plaintext collection as part of the proxy wrapper contract

Heimdall's policy language is deliberately limited to destination identity,
protocol, and port for one command cgroup. Complex upstream routing can still
live in the selected SOCKS5 service.
