# Architecture

Heimdall has one product path: wrap a command and proxy that command's
outbound connections.

```text
heimdall run -- command
        |
        | create transient cgroup and register proxy choice
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

The CLI is the product surface. It selects a named proxy, optionally chooses
the DNS mode, creates a child cgroup, executes the command, forwards its exit
status, and cleans up.

The daemon is implementation infrastructure. It loads the eBPF object,
maintains a local cgroup-to-proxy registry, runs the TCP relay and fake-IP DNS,
and reaps abandoned CLI cgroups. Its default eBPF policy is always bypass, so
an unregistered process cannot be redirected accidentally.

The configuration contains only named proxies, run defaults, and rarely-used
daemon listener settings. There is no workload selector language and no
orchestrator-shaped metadata.

## Connection lifecycle

1. `heimdall run` re-enters through `systemd-run --user --scope` when needed.
2. It creates an `heimdall-cli-*` cgroup below the delegated user subtree.
3. It registers that cgroup ID, proxy name, and DNS mode with the local daemon.
4. The child joins the cgroup and executes the requested command.
5. eBPF rewrites the child's TCP destinations to the local relay. DNS traffic
   is also redirected when `dns = "fake"`.
6. The relay recovers the original destination and connects through the
   selected SOCKS5 server.
7. The parent forwards the child's exit status and deregisters the cgroup.

If the parent is killed, the daemon's bounded cgroup scan removes the orphan
after it becomes empty.

## Non-goals

- cluster or container orchestration integration
- host-wide routing rules for services
- workload labels, annotations, or admission hooks
- a Web UI or public HTTP API as a primary interface
- TLS plaintext collection as part of the proxy wrapper contract

Destination-based routing belongs in the selected upstream proxy. Heimdall's
job is only to choose a proxy for one command and transport its connections.
