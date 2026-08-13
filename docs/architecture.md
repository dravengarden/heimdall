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
5. eBPF rewrites the child's TCP and connected UDP destinations to the local
   relay. DNS traffic is redirected over UDP or TCP when the policy uses fake
   DNS. System DNS is explicitly allowed to port 53. Connectionless non-DNS UDP
   is rejected fail-closed.
6. The relay recovers the original destination, evaluates the policy's ordered
   protocol rules, and routes, connects directly, or rejects it. UDP is a
   bounded one-request/one-response exchange; it does not yet preserve a
   long-lived upstream association.
7. Application bytes, including TLS records, pass through unchanged. Heimdall
   never uses SNI to reinterpret an IP destination: fake DNS produces a SOCKS5
   domain request, while system DNS preserves the resolved IP address.
8. The parent forwards the child's exit status and deregisters the cgroup.

If the parent is killed, the daemon's bounded cgroup scan removes the orphan
after it becomes empty.

Fake-IP mappings remain stable for the daemon lifetime. A depleted pool returns
DNS `SERVFAIL` instead of reassigning an address that an application may still
hold in its cache.

Redirect correlation keys include both address family and ephemeral source
port. IPv4 and IPv6 sockets may legally reuse the same port, so a port-only key
would allow concurrent dual-stack connections to overwrite each other. UDP
keeps its socket-cookie mapping for the connected socket lifetime so repeated
datagrams retain their original peer and `getpeername` remains transparent.

## Non-goals

- cluster or container orchestration integration
- host-wide routing rules for services
- workload labels, annotations, or admission hooks
- a Web UI or public HTTP API as a primary interface
- TLS plaintext collection as part of the proxy wrapper contract

Heimdall's policy language is deliberately limited to destination identity,
protocol, and port for one command cgroup. Complex upstream routing can still
live in the selected SOCKS5 service.
