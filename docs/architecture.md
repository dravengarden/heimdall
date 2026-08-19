# Architecture

Heimdall's default Linux path is one foreground command with one isolated data
plane. It does not require a persistent Heimdall daemon or a Web UI.

```text
heimdall run -- command
        |
        +-- transient user cgroup
        +-- per-run relay + fake DNS + JSONL writer
        +-- setup worker
        |      `-- attach eBPF, transfer FDs, then drop privilege
        |
        `-- wrapped command tree
                |
                `-- TCP/UDP -> policy -> SOCKS5, direct, or reject
```

## Ownership boundaries

The foreground `heimdall run` process is the session owner. It validates the
strict config, selects one named policy, creates the run log and transient
cgroup, binds kernel-assigned loopback relay and DNS ports, starts the child,
forwards its exit status, waits for every inherited descendant, and tears down
the session.

The hidden `heimdall __setup-worker` process is the only privileged component
in the default path. It accepts one `heimdall.setup/v2` request over an
inherited Unix socket, authenticates the caller and cgroup identity, creates
fresh unpinned maps, attaches eleven eBPF links to that cgroup, transfers four
map FDs and all link FDs with `SCM_RIGHTS`; runtime mode additionally returns
one already-opened perf ring per online CPU and startup-discovered OpenSSL
uprobe links. It then irrevocably drops to the authenticated caller and waits
only for its inherited socket. A marked close is normal teardown; an unmarked
EOF means the owner died, so the helper kills and removes that run's cgroup
before exiting. Runtime TLS also relies on the helper retaining complete Aya
probe state.
It never parses proxy credentials, opens event or blob files, terminates TLS, executes the workload, or
listens on a persistent socket.

The eBPF object is embedded in the single `heimdall` executable. Keeping the
received map and link FDs open makes kernel interception live for exactly the
foreground session. No default-path state is pinned below bpffs, and concurrent
runs do not share policy maps or listeners.

An optional viewer is only a reader of run manifests and JSONL files. It is not
an interception owner or a prerequisite for any run.

## Connection lifecycle

1. `heimdall run` loads config and resolves the selected policy. If necessary,
   it re-enters through `systemd-run --user --scope`, preserving the resolved
   global `--config` path, so it has a delegated cgroup subtree.
2. It creates an `heimdall-cli-*` cgroup and a user-owned
   `heimdall.run/v1` log directory.
3. It binds one kernel-assigned port across IPv4/IPv6 TCP/UDP relay listeners
   and another kernel-assigned port across IPv4/IPv6 UDP/TCP fake-DNS
   listeners.
4. The setup worker writes those endpoints and the selected policy bits into
   fresh per-run maps, attaches only the transient cgroup, and transfers owned
   FDs. Every mode keeps the now-unprivileged helper as a parent-death guard
   for the session. Failure here occurs before the child executes.
5. The child joins the cgroup and executes the requested argv. Processes
   outside this cgroup cannot be redirected by the per-run links.
6. eBPF redirects TCP, UDP, and fake-DNS traffic to the foreground listeners.
   System DNS remains explicit policy behavior.
7. The relay recovers the original destination, evaluates ordered protocol
   rules, and routes through SOCKS5, connects directly, or rejects. Events are
   appended to the run's JSONL segments; bounded payload blobs remain an
   explicit independent option in the same run store.
8. After the immediate child exits, Heimdall waits until `cgroup.events`
   reports `populated 0`, drains event delivery, closes listeners/maps/links,
   finalizes the run manifest, removes the cgroup, and returns the immediate
   child's exit status.

Closing the foreground owner's link FDs detaches interception. There is no
daemon restart or upgrade inside a normal run; one invocation is the lifecycle
boundary.

## DNS and UDP identity

Fake DNS maps names to synthetic addresses so the relay can recover a hostname
and issue a SOCKS5 domain request. Pool exhaustion returns `SERVFAIL`; an
address is never silently reassigned during the run.

TCP and connected IPv6 relay keys include address family and ephemeral source
port. IPv4 UDP assigns a distinct loopback token to each socket-and-destination
flow, and the receive hook restores the real peer address. This supports
connectionless multi-target IPv4 and concurrent `SO_REUSEPORT` sockets without
ambiguous responses.

Connected IPv6 and one-peer connectionless IPv6 use family-and-port
correlation, including IPv4-mapped destinations. A second peer on one
connectionless IPv6 socket or duplicate explicit IPv6 source-port ownership is
rejected fail-closed. HTTP/3 is acceptance-tested on single-family IPv4 and
native IPv6 paths; address-family migration is not claimed.

## Capture and TLS boundaries

Capture is a relay/application-boundary feature, not a kernel packet recorder.
`heimdall.event/v1` contains lifecycle, correlated fake-DNS exchanges, policy
decisions, flow/TLS metadata, and references to bounded content-addressed blobs
below the private run directory. JSONL never contains base64 payloads, and
there is no separate capture log or upload path.

TLS modes are explicit:

- `off` forwards TLS records without plaintext inspection.
- `relay` runs inside the foreground relay. It validates upstream TLS,
  presents a leaf signed by the user-owned Heimdall CA, and records plaintext
  after both handshakes. The parsed ClientHello is recorded before upstream
  verification, so SNI and offered ALPN remain available when a later handshake
  fails. Client trust is required; pinning and client-certificate mTLS are
  incompatible boundaries.
- `runtime` observes supported OpenSSL APIs without changing trust. The setup
  worker discovers already mapped `libssl` images at run startup, attaches
  probes globally while the per-run policy map filters events to the command
  cgroup, opens the per-CPU perf rings, and transfers those ring and link FDs.
  The unprivileged foreground owner only maps and reads the inherited
  rings. Every observed call emits `tls.runtime` plus a same-flow
  `flow.data` reference. Libraries loaded later or unsupported TLS
  implementations remain opaque.

The event or capture record identifies the actual observation boundary. A
selected TLS mode alone is never proof that plaintext was observed.

## Non-goals

- cluster or container orchestration integration
- host-wide routing rules or an always-on VPN
- workload labels, annotations, or admission hooks
- a Web UI or public HTTP API as a control plane

Heimdall's policy language stays limited to destination identity, protocol,
and port for one command cgroup. Complex upstream routing can remain in the
selected SOCKS5 service.
