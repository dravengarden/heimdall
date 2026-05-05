---
name: heimdall-run
description: |
  Wrap a CLI command so its egress goes through a heimdall connection
  (proxychains-style), without LD_PRELOAD. Triggers on "send this curl
  through the corp VPN", "route this CLI tool's traffic via a specific
  connection", "see plaintext for an ad-hoc command". Non-root: re-execs
  itself under `systemd-run --user --scope` so it lands in a writable
  cgroup. Resolves both IPv4 + IPv6 targets via heimdall fake-IP DNS by
  default. Defaults from `cli.run` in heimdall.<ext>; flags override.
license: MIT
metadata:
  author: heimdall
  version: '0.2.0'
---

# heimdall run — proxychains-style CLI proxy

Use when:
- An ad-hoc CLI tool (curl, git, wget, kubectl, vault, …) needs to
  egress through a specific named connection from `heimdall.<ext>`.
- The destination hostname is only resolvable via the upstream proxy's
  DNS scope (corp VPN, internal-only zones) — heimdall's fake-IP DNS
  hijack covers this.
- You want the tool's flows to appear in the heimdall flow log + tap
  alongside pod traffic, with a label.

## Command

```bash
heimdall run [OPTIONS] -- <command> [args ...]
```

The `--` separator is required when the wrapped command has its own
flags. Run `heimdall help run` for the full option list (or
`heimdall help` for every subcommand at once — both go through the
recursive AI-friendly dump).

### Common options

| Option | Meaning |
|---|---|
| `-c, --connection <NAME>` | Connection name (or reserved `system`). Highest priority. |
| `-p, --profile <NAME>` | Apply `cli.run.profiles.<NAME>` from heimdall.<ext> before flag overrides. |
| `--observe <true\|false>` | Capture plaintext via the tap for this run. |
| `--dns <fake\|system>` | DNS strategy. `fake` (default) hijacks `:53` lookups so the wrapped command resolves via heimdall's fake-IP DNS — the upstream proxy then resolves the hostname in its own scope (corp VPN). `system` skips the hijack and uses the host resolver. |
| `--tag <STRING>` | Free-form label, surfaces in flow log entries. |
| `--print-decision` | Resolve the merged decision and print as JSON; don't run anything. |
| `--keep-cgroup` | Don't rmdir the transient cgroup on exit (debug aid). |

## Resolution order

```
flag (e.g. --connection X / --dns system)
  > cli.run.profiles[--profile NAME]   in heimdall.<ext>
  > cli.run.default                     in heimdall.<ext>
  > compiled-in defaults (connection="default", observe=true, dns="fake")
```

## Examples

### Verify a profile resolves the way you expect

```bash
heimdall run -p corp --print-decision -- echo unused
# {
#   "connection": "corp",
#   "observe": true,
#   "dns": "fake",
#   "tag": "corp-cli"
# }
```

### Send a curl through a named connection (corp-internal hostname)

```bash
heimdall run -p corp -- curl -ksSm 5 https://vault.prod.corp.com/
# tunnel established connection=corp dst=vault.prod.corp.com
#                    via=<UPSTREAM_IP>:1080
```

### Public hostname through the default connection

```bash
heimdall run -- curl -ksSm 5 https://www.cloudflare.com/
# Works for both IPv4 and IPv6; --dns fake gives both A + AAAA fake IPs.
```

### Skip the DNS hijack (use host resolver)

```bash
heimdall run --connection direct --dns system -- curl https://example.com/
# Resolves via systemd-resolved / nscd; only the connect path is
# intercepted (relay sees the real IP, atyp=ip in the flow log).
```

### Override observe per invocation

```bash
heimdall run -p peek --observe false -- npm install
```

### Run with a custom tag (visible in flow log + tap messages)

```bash
heimdall run --tag "release-build" -- cargo publish
```

## What happens under the hood

1. Loads heimdall.<ext>, merges profile + flags into a `RunDecision`
   (connection, observe, dns, tag).
2. Validates connection name against `connections:` (and the
   reserved `system` tag).
3. Detects whether the current process is under `user@<UID>.service`
   (where the user has cgroup write permission). If not, re-execs
   `systemd-run --user --scope --quiet -- heimdall run --no-reentry …`
   so it lands in `app.slice/run-<id>.scope/`.
4. mkdir's a sibling cgroup `<parent>/heimdall-cli-<pid>-<rand>/`,
   reads its inode → cgroup_id (cgroup v2 invariant).
5. POSTs `{ cgroup_id, connection, observe, dns }` to
   `/api/cli/register`. The daemon writes the userspace
   `cli_overrides` map (relay reads) and the `CGROUP_POLICY` BPF
   map. When `dns: "fake"` the policy byte includes
   `POLICY_DNS_HIJACK` so eBPF rewrites `:53` connects/sendmsgs to
   heimdall's fake-IP DNS.
6. When `dns: "fake"`, generates per-cgroup_id tmp shim files
   (`/tmp/heimdall-cli-{nsswitch,resolv}-<id>.conf`).
7. Forks. Child:
   - writes its PID to `cgroup.procs` (joins the new cgroup),
   - strips proxy env vars (`http_proxy`, `https_proxy`, …) so the
     wrapped command goes direct,
   - restores default `SIGINT`/`SIGTERM`,
   - if `dns=fake`: `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, sets up
     uid/gid maps, makes `/` mounts private, bind-mounts the shim
     `nsswitch.conf` + `resolv.conf` over `/etc/...`, AND bind-mounts
     `/dev/null` over `/var/run/nscd/socket` so glibc's NSS doesn't
     bypass our shimmed nsswitch via nscd,
   - `execvp` the wrapped command.
   Parent `waitpid`s.
8. On child exit, POSTs `/api/cli/deregister?cgroup_id=N`, rmdirs
   the cgroup, removes the tmp shim files. Forwards child exit code
   (or `128 + signal`) as `heimdall run`'s own.

## Why this is non-trivial

If you're wondering why this can't be a simple `LD_PRELOAD` shim:

- Static Go binaries: LD_PRELOAD has no effect on them
- setuid binaries: kernel ignores LD_PRELOAD
- UDP destinations + DNS: connect-only shims miss them

heimdall sidesteps all of that by intercepting at the kernel
syscall level via cgroup-attached eBPF programs (`connect4`,
`connect6`, `udp4_sendmsg`, `udp6_sendmsg`, `skb_egress`).

## Three non-obvious bits the implementation handles

### 1. v2raya host TPROXY would otherwise eat the redirected packet

heimdall's connect4 rewrites the dst to the relay socket
(cilium_host:12345). On a NixOS host running v2raya for system-wide
proxying, v2raya's mangle-table TPROXY rules would see this as
host-originated traffic and divert it to v2raya's port 52345 —
heimdall relay never sees it. The NixOS module
`services/k0s/default.nix:k8s-v2raya-fix` adds two iptables rules
to TP_OUT / TP_PRE that whitelist the relay endpoint
(`dst=10.244.0.41:12345 → RETURN/K8S_BYPASS`). Same idea for
ip6tables and `[::1]:12345`.

### 2. PolicyEngine reconcile would otherwise wipe the registration

The reconcile loop (5s tick) drops `CGROUP_POLICY` entries it
doesn't recognise as belonging to a current pod. CLI-registered
entries are flagged via a separate `external` set so reconcile
skips them — see `policy.rs::register_external` /
`deregister_external`.

### 3. NixOS NSS goes via nscd → systemd-resolved over D-Bus

eBPF can rewrite UDP/TCP destinations but it can't intercept Unix
domain sockets. Glibc's NSS dispatches to nscd first
(`/var/run/nscd/socket`), which would resolve hostnames in its own
mount namespace using the host's nsswitch.conf — bypassing our
shimmed `/etc/nsswitch.conf` entirely. The `dns=fake` shim therefore
also bind-mounts `/dev/null` over the nscd socket so glibc falls
through to direct NSS lookup, hits our shimmed nsswitch
(`hosts: files dns`), then nss-dns reads our shimmed resolv.conf
(`nameserver 127.0.0.1`), then libc opens UDP `127.0.0.1:53` →
eBPF DNS hijack → heimdall fake-IP DNS.

## IPv6

Both connect6 and udp6_sendmsg are wired. `dns=fake` synthesises
AAAA records from `runtime.fakeIp6Cidr` (default
`fc00:198:19::/96`). For dual-stack hostnames curl picks v6 first
by default; the path is identical to v4 modulo address family. No
`-4` workaround needed.

## Lifecycle: orphan cleanup

`kill -9` on a `heimdall run` parent leaks the transient cgroup +
BPF policy entry + cli_overrides map row. The daemon runs a
periodic GC pass (every 30s) that walks
`/sys/fs/cgroup/user.slice` for `heimdall-cli-*` directories with
`cgroup.events: populated 0` (no live processes), then tears down
the userspace maps, BPF policy entry, and rmdirs the cgroup.
Idempotent and safe — clean exits don't go through this path
because the parent runs deregister + rmdir explicitly.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `unknown connection 'foo'` | Misspelled `--connection` or stale profile | Run with `--print-decision` to see resolution; check `connections:` in heimdall.<ext> |
| `unknown profile 'foo'` | `--profile` doesn't match a key in `cli.run.profiles` | Read `cli.run.profiles` in `/etc/heimdall/heimdall.<ext>` |
| `Could not resolve host` (with `dns=fake`) | Mount-namespace shim failed (e.g. user namespaces disabled in the kernel) | Try `--dns system` as a workaround; check `unshare(CLONE_NEWUSER \| CLONE_NEWNS)` works for your user |
| `Failed to connect ... port N after 0 ms` | Connection rewrote to relay but relay isn't accepting (daemon restart in progress) | `heimdall status` to confirm `relay ok (port reachable)` |
| `mkdir … failed (parent must be user-writable …)` | systemd-user-unit not running for current user | `systemctl --user is-active default.target` should return active; if not, log out + back in |
| `policy engine not initialised … retry in a moment` | Daemon just started, k8s informer hadn't synced when register fired | Re-run after `heimdall status` confirms `connections=N` |
| `exec systemd-run --user --scope … (is systemd-user running?)` | `systemd-user@<UID>.service` is masked or not configured | Same as above |

## Related skills

- `heimdall-flows` — see what your wrapped command actually sent
- `heimdall-status` — confirm daemon health before debugging routing
- `heimdall-config` — declare `cli.run.profiles` for new connection bundles
