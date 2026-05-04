---
name: heimdall-run
description: |
  Wrap a CLI command so its egress goes through a heimdall connection
  (proxychains-style), without LD_PRELOAD. Triggers on "send this curl
  through the corp VPN", "route this CLI tool's traffic via a specific
  connection", "see plaintext for an ad-hoc command". Non-root: re-execs
  itself under `systemd-run --user --scope` so it lands in a writable
  cgroup. Defaults from `cli.run` in heimdall.<ext>; flags override.
  IPv4 only — pass `-4` to curl/etc. or use a target with no AAAA
  record, otherwise the connection bypasses heimdall via IPv6.
license: MIT
metadata:
  author: dravengarden
  version: '0.1.0'
---

# heimdall run — proxychains-style CLI proxy

> **IPv4 ONLY.** heimdall's eBPF program is `cgroup_inet4_connect`
> (no IPv6 sibling yet). For wrapped commands that resolve to AAAA,
> the IPv6 path bypasses heimdall and goes through whatever the
> host normally uses (typically v2raya for users with proxy env
> set). Force IPv4 with curl `-4`, `wget --inet4-only`, or env
> `RES_OPTIONS="single-request-reopen"` plus a v4-only DNS resolver.
> Filed as a follow-up: add `cgroup_inet6_connect`.

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

## Why this is non-trivial

If you're wondering why this can't be a simple `LD_PRELOAD` shim:

- Static Go binaries: LD_PRELOAD has no effect on them
- setuid binaries: kernel ignores LD_PRELOAD
- UDP destinations + DNS: connect-only shims miss them

heimdall sidesteps all of that by intercepting at the kernel
syscall level via cgroup-attached eBPF programs.

## Two non-obvious bits the implementation handles

### 1. v2raya host TPROXY would otherwise eat the redirected packet

heimdall's connect4 rewrites `dst` to the relay socket
(cilium_host:12345). On a NixOS host running v2raya for system-wide
proxying, v2raya's mangle-table TPROXY rules would otherwise see
this as host-originated traffic and divert it to v2raya's port
52345 — heimdall relay never sees it. NixOS module
`services/k0s/default.nix:k8s-v2raya-fix` adds two iptables rules
to the TP_OUT/TP_PRE chains that whitelist the relay endpoint
(dst=10.244.0.41:12345 → RETURN/K8S_BYPASS). Required.

### 2. PolicyEngine reconcile would otherwise wipe the registration

The reconcile loop (5s tick) drops CGROUP_POLICY entries it
doesn't recognise as belonging to a current pod. CLI-registered
entries are flagged via a separate `external` set so reconcile
skips them — see `policy.rs::register_external` /
`deregister_external`.

## Failure to intercept — IPv6 bypass

`heimdall run -- curl https://...` will fall back to direct egress
(via the host's normal proxy if any) when the destination has an
AAAA record and curl prefers IPv6. Workarounds:
- pass `-4` to curl
- use a v4-only resolver target
- await `cgroup_inet6_connect` support (TODO)

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
