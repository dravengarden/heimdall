# Daemonless runtime design

Status: implemented for all Linux decrypt modes. Runtime OpenSSL coverage is
startup-discovered: a representative `libssl` image must already be mapped.

## Decision

The default product is one foreground command:

```text
heimdall run -- command
```

`heimdall run` owns a short-lived session supervisor for exactly as long as the
wrapped process tree exists. The supervisor owns interception, relay, DNS, TLS
inspection, event writing, and cleanup. When the process tree is empty, no
Heimdall process, listener, cgroup, eBPF link, map, or control socket remains.

Heimdall MUST NOT install, enable, start, or silently connect to a persistent
daemon in the default path. A Web UI is optional, read-only, and started
explicitly. It is not required for proxying, TLS inspection, capture, or agent
analysis.

This is a lifecycle redesign, not a promise that proxying can happen without a
userspace process. eBPF redirects traffic; a userspace relay still has to speak
SOCKS5 and forward TCP/UDP while the wrapped command is running.

## Product invariants

1. Installing Heimdall installs one `heimdall` executable. The Linux eBPF
   object remains embedded in it.
2. `heimdall run` is foreground-owned. Signals, exit status, descendants, and
   cleanup have one parent lifecycle.
3. No persistent service is a prerequisite for proxying or TLS inspection.
4. Privilege is acquired only for the smallest operation and shortest lifetime
   required by the selected backend. Heimdall never grants file capabilities
   to the complete CLI binary.
5. Every run has an isolated ID, cgroup, relay ports, maps, links, event
   directory, and control socket. Concurrent runs do not share mutable policy
   state.
6. Failure to initialize interception fails before the child starts. Failure
   after the child starts is fail-closed for traffic owned by that run.
7. JSONL on disk is the evidence source of truth. The CLI and optional UI are
   consumers of the same files.
8. The optional UI can never enable TLS interception, alter policy, or become
   a hidden control plane.

## Runtime shape

```text
terminal / agent
      |
      v
heimdall run (unprivileged session owner)
      | creates run directory and private control socket
      | validates config and selects a backend
      |
      +---- minimal setup worker
      |       validates cgroup and attaches per-run eBPF links
      |       passes owned FDs back, then drops privilege
      |
      +---- relay + DNS + optional TLS boundary
      |       loopback ports allocated per run
      |       writes ordered events and blobs
      |
      +---- wrapped process tree in the run cgroup
      |
      `---- teardown after cgroup.events reports populated=0
              close links/maps/listeners, remove cgroup/socket, finalize run
```

The session owner is not a daemon: it stays attached to the invocation, has no
machine-wide API, and exits deterministically. It may fork internal workers,
but all workers are in the same lifetime and are reaped before `heimdall run`
returns.

## Privilege boundary

The Linux cgroup/eBPF backend needs privileged setup on ordinary systems. The
preferred design is a tiny, auditable privileged re-exec mode within the same
installed binary:

- the unprivileged parent validates the complete request first;
- the setup worker accepts a narrow, versioned request over an inherited Unix
  socket, not arbitrary CLI arguments;
- it attaches only the requested transient cgroup and creates per-run BPF
  resources;
- it passes FDs to the parent with `SCM_RIGHTS` and drops privilege before the
  workload starts;
- it cannot open the capture directory, parse SOCKS credentials, terminate
  TLS, execute the child, or keep a listener alive.

Runtime TLS discovers already mapped `libssl` images during privileged setup.
The worker attaches those probes globally, but the per-run `CGROUP_POLICY` map
causes the eBPF programs to emit only for the wrapped command cgroup. It
opens the per-CPU perf rings and transfers those ring FDs and the uprobe links
to the foreground owner. Aya's complete probe state must remain alive, so the
now-unprivileged helper waits for the session socket to close and is reaped by
the foreground owner. A library loaded only after child exec is outside the current coverage;
dynamic run-scoped attachment remains a possible future extension, not a
reason to keep a persistent broker.

The authorization mechanism may be `sudo` initially and Polkit later. Both are
per-run authorization paths, not persistent Heimdall services. Installing a
setuid binary or ambient capabilities on the whole CLI is out of scope.

A future rootless backend may use a private network namespace plus a user-mode
network stack. It must expose its reduced TCP/UDP, DNS, and performance
capabilities through `heimdall agent`; it must not silently replace the eBPF
backend.

## Per-run kernel state

The fixed relay-port prerequisite and shared runtime state have been removed
from the default path. The foreground backend uses:

- kernel-assigned loopback TCP, UDP, and DNS ports;
- one transient cgroup per run;
- one map set and one link set per run;
- FD-owned links and maps instead of persistent bpffs pins;
- relay endpoint values populated before the child can enter the cgroup;
- an explicit ready barrier before `exec`.

Normal process exit closes the owning FDs and detaches the links. On abrupt
owner death, the unprivileged setup helper observes unmarked socket EOF, kills
the command cgroup, waits for it to empty, and removes it. No pinned state
exists in either path.

This removes daemon-restart continuity. That is intentional: one invocation is
the lifecycle boundary. There is no upgrade or restart in the middle of a run.

The link transaction retains attached link FDs without creating bpffs pins.
Object loading creates fresh unpinned maps for every run.

The setup-worker transport now has a strict `heimdall.setup/v2` contract. It
uses length-delimited JSON for one validated cgroup, relay/DNS ports, and the
known kernel policy bits, followed by one fixed-order `SCM_RIGHTS` bundle of
four correlation maps and eleven cgroup links. Runtime mode appends a counted
set of OpenSSL uprobe links followed by one already-opened perf ring for each
reported online CPU. Received descriptors are close-on-exec. Unknown fields,
unknown policy bits, path traversal, manifest
changes, missing descriptors, and ancillary truncation fail closed. Parent-side
typed map reconstruction and process-owned link transfer are implemented.

The hidden setup worker is now wired and VM-verified. It authenticates the Unix
socket peer against the sudo caller when available, confines non-root callers
to their own user slice, rejects non-canonical paths and cgroup inode
mismatches, initializes fresh maps, attaches only the requested cgroup, sends
the fixed FD bundle, and drops to the authenticated caller. Every mode waits
on inherited-socket EOF as a parent-death guard; runtime mode also retains Aya
probe state. Graceful teardown is explicitly marked. Unmarked EOF kills and
removes the command cgroup before the helper exits. No persistent daemon or
long-lived privileged listener is required.
`heimdall run` invokes it once after binding per-run listeners and before
executing the child.

## Process and signal lifecycle

The session owner MUST:

1. validate configuration and logs before acquiring privilege;
2. create the run manifest with state `starting`;
3. initialize all listeners, maps, links, and TLS prerequisites;
4. emit `run.ready`, then start the child;
5. forward terminal signals and preserve job-control behavior;
6. preserve the immediate child's exit status;
7. keep the policy active while inherited descendants remain in the cgroup;
8. on timeout or fatal relay failure, terminate the process tree and report a
   stable error;
9. emit `run.close`, fsync the final segment and manifest, then remove runtime
   objects.

`heimdall run` may detach only through a future explicit command and explicit
contract. It must never detach as an optimization.

## TLS inspection

TLS remains an explicit run mode, not a daemon feature.

- `off`: proxy bytes without plaintext inspection.
- `runtime`: observe supported OpenSSL APIs through startup-discovered probes
  owned by the foreground session. It changes no trust, but does not observe
  unsupported or later-loaded TLS libraries.
- `relay`: terminate TLS in the per-run relay using explicitly initialized and
  trusted CA material.

Both runtime discovery and relay handshakes are owned only for that run. Both
modes identify the actual observation boundary; neither mode requires a UI.

## Optional Web UI

The planned `heimdall ui` is a separate, unprivileged, read-only process:

```text
heimdall ui [--run RUN_ID] [--listen 127.0.0.1:0]
```

It reads manifests, JSONL segments, and referenced blobs directly. For a live
run it follows finalized records as new bytes and segments appear. It does not
receive pushed events over an application port, because that would create two
sources of truth and couple capture reliability to UI availability.

The default bind is loopback with an ephemeral port. Non-loopback exposure,
authentication, and remote access are separate future decisions. Closing the
UI has no effect on a run. Starting a run has no effect on the UI.

## Agent contract

`heimdall agent` remains read-only and single-document JSON.
`heimdall.agent/v7` reports:

- selected backend and whether per-run authorization is required;
- the explicit `daemon_required = false` foreground ownership boundary;
- supported TCP, UDP, DNS, and TLS boundaries;
- event and run-manifest schema versions;
- argv arrays for schema, list, query, tail, rotate, and prune commands;
- whether an active run can accept a manual rotate request;
- exact limitations of any rootless or macOS fallback.

Readiness means a new run can be attempted; there is no service health
dependency.

## Performance acceptance

Daemonless is the default unless measurements prove it unusable. Acceptance
must measure separately:

- cold start to child `exec`;
- privilege prompt and setup time;
- TCP connect latency and steady throughput;
- UDP and QUIC latency, throughput, and loss;
- JSONL metadata-only, payload, runtime TLS, and relay TLS overhead;
- 1, 10, and 50 concurrent runs;
- teardown latency and leaked kernel/runtime objects after normal exit,
  signals, parent crash, and out-of-disk failures.

A persistent acceleration service may be considered only after these numbers
exist. If added, it is an explicit opt-in profile with a visible capability
contract; `heimdall run` must never auto-enable it.

## Migration plan

### Phase 1: event store — available

- `heimdall.event/v1`, `heimdall.run/v1`, segment rotation, schema discovery,
  integrity verification, retention, and `heimdall logs` commands are active.
- Lifecycle plus TCP/UDP metadata are emitted; content-addressed blobs and
  derived TLS/HTTP events remain on the event-log roadmap.
- `heimdall.capture/v1` remains the explicit bounded payload path.

### Phase 2: foreground session owner — available

- Relay, DNS, relay TLS, capture, and lifecycle ownership are grouped under the
  foreground session boundary.
- Ports and mutable state are allocated per run.
- Concurrent sessions and process-tree cleanup are proven in the VM.

### Phase 3: transient eBPF backend — available

- Global pins and registrations are replaced by FD-owned per-run links and
  maps in the foreground modes.
- The narrow setup-worker protocol and sudo authorization path are active.
- Daemonless is the default for all decrypt modes; no service is required.

### Phase 4: remove the old daemon contract — available

- `heimdall daemon`, its service unit, registration API, persistent journal,
  global bpffs state, health contract, cleanup CLI, and orphan-GC loop are
  removed.
- `heimdall.agent/v7` describes only the foreground execution owner.
- The session helper supplies fail-closed parent-death cleanup without a
  listener or cross-run lifetime.

### Phase 5: optional UI

- Build the read-only viewer only after event/log contracts are stable.
- Test that every UI view can be reconstructed from files without a live run.

## Acceptance criteria

The redesign is complete only when:

- a clean machine can install one binary and run a command without enabling a
  Heimdall service;
- `pgrep`, listening-socket inspection, cgroup inspection, and bpffs inspection
  show no Heimdall runtime residue after the process tree exits;
- two concurrent runs can select different policies and rotate logs
  independently;
- killing the parent, filling the event volume, or breaking the upstream fails
  predictably without direct-egress fallback;
- an agent can discover the schema and answer common flow/TLS questions with
  the documented CLI or standard Linux tools;
- the UI can be absent, started late, restarted, or closed without changing
  proxy or capture behavior.
