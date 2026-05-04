---
name: heimdall-run
description: |
  EXPERIMENTAL — wrap a CLI command so its egress goes through a heimdall
  connection (proxychains-style), without LD_PRELOAD. Triggers on
  "send this curl through the corp VPN", "route this CLI tool's
  traffic via a specific connection", "see plaintext for an ad-hoc
  command". Non-root: re-execs itself under `systemd-run --user
  --scope` so it lands in a writable cgroup. Defaults from `cli.run`
  in heimdall.<ext>; flags override.
license: MIT
metadata:
  author: dravengarden
  version: '0.1.0-experimental'
---

# heimdall run — proxychains-style CLI proxy

> **STATUS: EXPERIMENTAL.** All control-plane plumbing is in place
> (cgroup creation, HTTP register/deregister, profile resolution,
> fork/exec, signal forwarding, exit-code propagation). The eBPF
> *redirect* for processes under `user.slice` is **not yet firing
> reliably** — the cgroup is registered with the daemon but
> `connect4` doesn't intercept user-side connect() calls in the
> current attach configuration. Pod traffic is unaffected. See
> "Known issue" below.
>
> Use it for testing the mechanism + flow logging; don't depend on it
> for security-critical egress paths until the eBPF gap is fixed.

Use when:
- An ad-hoc CLI tool (curl, git, wget, kubectl, …) needs to egress
  through a specific named connection from `heimdall.<ext>`.
- You want the tool's flows to appear in the heimdall flow log + tap
  alongside the pod traffic, with a label.

## Command

```bash
heimdall run [OPTIONS] -- <command> [args ...]
```

The `--` separator is required when the wrapped command has its own
flags. Run `heimdall --help` (recursive) for the full option list.

### Common options

| Option | Meaning |
|---|---|
| `-c, --connection <NAME>` | Connection name (or reserved `system`). Highest priority. |
| `-p, --profile <NAME>` | Apply `cli.run.profiles.<NAME>` from heimdall.<ext> before flag overrides. |
| `--observe <true\|false>` | Capture plaintext via the tap for this run. |
| `--tag <STRING>` | Free-form label, surfaces in flow log entries. |
| `--print-decision` | Resolve the merged decision and print as JSON; don't run anything. |
| `--keep-cgroup` | Don't rmdir the transient cgroup on exit (debug aid). |

## Resolution order

```
flag (e.g. --connection X)
  > cli.run.profiles[--profile NAME]   in heimdall.<ext>
  > cli.run.default                     in heimdall.<ext>
  > compiled-in defaults (connection="default", observe=true)
```

## Examples

### Verify a profile resolves the way you expect

```bash
heimdall run -p corp --print-decision -- echo unused
# {"connection": "corp", "observe": true, "tag": "corp-cli"}
```

### Send a curl through a named connection

```bash
heimdall run -p corp -- curl -ksSm 5 https://internal.example.com/
heimdall run --connection direct -- git fetch origin
```

### Override observe per invocation

```bash
heimdall run -p peek --observe false -- npm install
```

### Run with a custom tag (visible in flow log + tap messages)

```bash
heimdall run --tag "release-build-2026-05-04" -- cargo publish
```

## What happens under the hood

1. Loads heimdall.<ext>, merges profile + flags into a `RunDecision`.
2. Validates connection name against `connections:` (and the
   reserved `system` tag).
3. Detects whether the current process is under `user@<UID>.service`
   (where the user has cgroup write permission). If not, re-execs
   `systemd-run --user --scope --quiet -- heimdall run --no-reentry …`
   so it lands in `app.slice/run-<id>.scope/`.
4. mkdir's a sibling cgroup `<parent>/heimdall-cli-<pid>-<rand>/`,
   reads its inode → cgroup_id (cgroup v2 invariant).
5. POSTs `cgroup_id + connection + observe` to the daemon's
   `/api/cli/register`. The daemon writes both the userspace
   `cli_overrides` map (relay reads) and the `CGROUP_POLICY` BPF map.
6. Forks. Child writes its PID to `cgroup.procs`, strips proxy env
   vars, restores default signal handlers, exec's the wrapped
   command. Parent waits.
7. On child exit, POSTs `/api/cli/deregister?cgroup_id=N` and rmdir's
   the cgroup. Forwards the child's exit code (or 128 + signal) as
   `heimdall run`'s own.

## Known issue (EXPERIMENTAL caveat)

**Symptom**: child commands run successfully and reach their
destinations (HTTP responses normal), but their connections show up
in the flow log with `connection_name: "bypass"` instead of the
requested connection — the eBPF `connect4` hook isn't redirecting
them to the relay.

**Root cause**: the daemon attaches `cgroup_sock_addr` + `cgroup_skb`
at both `runtime.cgroup` (typically `/sys/fs/cgroup/kubepods`) and
`/sys/fs/cgroup/user.slice`. The kubepods attach works for pods.
The user.slice attach reports success at startup but the program
doesn't appear to fire for descendants.

**Suspected**:
- aya 0.13 may track multiple cgroup attaches under one program in a
  way that makes only one effective.
- Cilium attaches its own cgroup_sock_addr programs that may
  interact with heimdall's at the user.slice level.
- Kernel cgroup_sock_addr hierarchical inheritance interaction with
  systemd's user-slice scopes.

**Investigation tools needed** (not currently installed on the
host): `bpftool` (`pkgs.bpftools` in NixOS), `bpftrace`, plus
turning on aya's debug logging. Filed as a follow-up.

**Workaround for now**: the planned `cli` config schema +
`heimdall run` register/deregister API are stable; once the eBPF
attach is sorted, no CLI surface changes are needed. In the
meantime, `heimdall run --print-decision` is useful for validating
profile resolution.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `unknown connection 'foo'` | Misspelled `--connection` or stale profile | Run with `--print-decision` to see resolution; check `connections:` in heimdall.<ext> |
| `unknown profile 'foo'` | `--profile` doesn't match a key in `cli.run.profiles` | List declared profiles via `heimdall --help` (or read heimdall.<ext>) |
| `mkdir … failed (parent must be user-writable …)` | systemd-user-unit not running for current user | `systemctl --user is-active default.target` should return active; if not, log out + back in |
| `policy engine not initialised … retry in a moment` | Daemon just started, k8s informer hadn't synced when register fired | Re-run after `heimdall status` confirms `connections=N` |
| `exec systemd-run --user --scope … (is systemd-user running?)` | `systemd-user@<UID>.service` is masked or not configured | Same as above |

## Related skills

- `heimdall-flows` — see what your wrapped command actually sent
- `heimdall-status` — confirm daemon health before debugging routing
- `heimdall-config` — declare `cli.run.profiles` for new connection bundles
