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
   IPv6 sendmsg uses a single-peer family-and-port fallback, including
   IPv4-mapped destinations used by common dual-stack QUIC clients. Ambiguous
   IPv6 multi-target traffic remains fail-closed. Explicit IPv6 source-port
   ownership is reserved per live socket so a shared relay tuple cannot return
   data to the wrong process. DNS traffic is redirected
   over UDP or TCP when the policy uses fake DNS. System DNS is explicitly
   allowed to port 53.
6. The relay recovers the original destination, evaluates the policy's ordered
   protocol rules, and routes, connects directly, or rejects it. Connected UDP
   reuses one bidirectional upstream association per socket. IPv4 connectionless
   UDP reuses one association per socket and destination.
7. Application bytes, including TLS records, pass through unchanged. When
   capture is enabled, the relay writes its observed TCP stream chunks or UDP
   datagrams to one bounded JSONL file per flow before forwarding them. SOCKS5
   handshakes and UDP framing are excluded. TLS remains ciphertext unless one
   of the two explicit decrypt modes is enabled. Heimdall never uses SNI to
   reinterpret an IP destination: fake DNS produces a SOCKS5 domain request,
   while system DNS preserves the resolved IP address.
8. After the immediate child exits, the parent keeps the policy registered
   until `cgroup.events` reports that every inherited descendant has exited.
   It then deregisters the cgroup and returns the immediate child's exit status.

If the parent is killed, the daemon's bounded cgroup scan removes the orphan
after it becomes empty.

Fake-IP mappings remain stable for the current boot and survive a daemon
restart. A depleted pool returns DNS `SERVFAIL` instead of reassigning an
address that an application may still hold in its cache.

The daemon pins its eBPF maps and cgroup links below `/sys/fs/bpf/heimdall`.
Every replacement loads against the same maps, then atomically redirects each
stable cgroup link to its new program with an expected-old-program
`BPF_LINK_UPDATE`. The daemon retains both program generations until every link
and relay listener is ready. Any failure rolls already-replaced links back in
reverse order; only a complete generation is committed. Registered traffic therefore remains
intercepted during a daemon restart and fails closed while the loopback relay is
unavailable. A root-only runtime journal records active CLI cgroup
registrations and fake-DNS mappings. Once the replacement daemon is ready, it
restores userspace decisions for still-populated cgroups and removes stale
registrations. Existing TCP or UDP relay sessions are not preserved, so this is
enforcement continuity rather than full connection continuity. `heimdall agent`
exposes both boundaries through `capabilities.lifecycle`.

Capture is a relay/application-boundary facility, not a kernel packet recorder. Its
`heimdall.capture/v1` files preserve ordered open/data/close events and count
both wire directions under one per-flow byte budget. The root-only output
directory is permission-checked before eBPF attachment. Storage retention remains an
operator responsibility. Runtime decryption pairs OpenSSL entry and return
uprobes so it emits only successfully transferred `SSL_read`, `SSL_read_ex`,
`SSL_write`, and `SSL_write_ex` application bytes through a bounded perf array
without terminating TLS. Startup requires at least one attachable loaded
OpenSSL image. Relay
decryption classifies ClientHello at the relay, validates upstream TLS, presents
a Heimdall-CA-signed leaf to the client, and records plaintext after both
handshakes. The capture `payload` field distinguishes these records from opaque
transport.

A pinned bootstrap array records the map-layout schema. A binary rejects an
unknown schema before loading or replacing programs and points the operator at
the explicit cleanup command. Cleanup takes the same exclusive lifecycle lock
as the daemon and refuses to remove pins while any registration or populated
command cgroup exists.

TCP and connected IPv6 relay keys include both address family and ephemeral
source port. IPv4 UDP instead rewrites each socket-and-destination flow to a
distinct address in `127/8`; `recvmsg4` restores the real source address on the
return path. This avoids ambiguity for an unconnected socket targeting several
peers and for concurrent `SO_REUSEPORT` sockets. Connected IPv6 keeps the
family-and-port path, including one connectionless peer per socket. A second
peer on one IPv6 socket is rejected by `sendmsg6`; a duplicate explicit IPv6
source-port bind is rejected before traffic can become ambiguous. Socket
release clears both ownership records. The daemon verifies socket liveness before returning every
upstream datagram and closes the session when the socket disappears, its CLI
cgroup deregisters, orphan GC runs, or the session remains idle for 60 seconds.

## Non-goals

- cluster or container orchestration integration
- host-wide routing rules for services
- workload labels, annotations, or admission hooks
- a Web UI or public HTTP API as a primary interface

Heimdall's policy language is deliberately limited to destination identity,
protocol, and port for one command cgroup. Complex upstream routing can still
live in the selected SOCKS5 service.
