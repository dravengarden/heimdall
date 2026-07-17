# Runbook

## Daily ops

### Building a new daemon

```bash
# eBPF first (its build artifact is include_bytes!'d into the daemon).
# Uses the pinned nightly + rust-src/build-std and matching LLVM linker.
nix develop .#ebpf -c bash -c \
  'cd heimdall-ebpf && cargo-nightly build --locked --release'

# UI (only when components/ or hooks/ changed)
( cd heimdall-ui && deno install --frozen --allow-scripts && deno task typecheck && deno task build )

# Daemon (embeds the UI bundle via rust-embed)
nix develop -c cargo build --workspace --all-features --locked --release
```

### Deploying

Pure-Nix deploy lives in the companion `services/heimdall/` (NixOS
module). For ad-hoc deploys directly from a build:

```bash
sudo install -m 0755 target/release/heimdall /usr/local/bin/heimdall
sudo systemctl restart heimdall
sudo journalctl -u heimdall -f       # tail logs
```

A clean restart should print roughly, in order:

```
config loaded                           ← /etc/heimdall/heimdall.{ncl,toml,json,yaml} auto-discovered
all connections resolved
flow store ready
unit resolver ready
fake-IP DNS server ready
HTTP API listening
relay IP written to BPF map
relay IPv6 written to BPF map
DNS hijack target written to BPF maps   ← DNS_ADDR_V4 + DNS_ADDR_V6 + DNS_PORT_V6
eBPF connect4 attached cgroup=/sys/fs/cgroup/system.slice
eBPF connect4 attached (extra) cgroup=/sys/fs/cgroup/user.slice
eBPF connect6 attached cgroup=/sys/fs/cgroup/system.slice
eBPF connect6 attached (extra) cgroup=/sys/fs/cgroup/user.slice
eBPF sendmsg attached prog=udp4_sendmsg
eBPF sendmsg attached prog=udp6_sendmsg
eBPF skb_egress attached cgroup=/sys/fs/cgroup/system.slice
eBPF skb_egress attached (extra) cgroup=/sys/fs/cgroup/user.slice
policy engine started
orphan-cgroup GC spawned (interval 30s)
policy: reconciled writes=N deletes=0 cgroups=K
bypass: synthetic flow consumer started
tap: libssl candidates discovered count=A
tap: Go TLS binaries discovered count=B
tap: libssl uprobes attached path=...   (×A)
tap: Go Read RET sites found ret_sites=7   (×B)
tap: go_tls_write attached path=...   (×B)
tap: rustls uprobes attached path=...   (×C)
tap: started (Phase B) attached_libs=A+B+C persist=true
tap: store writer started
heimdall ready listen=[::]:12345 configured=0.0.0.0:12345
bootstrap: synthesized flows for pre-existing connections inserted=N
bootstrap: pre-existing connections recorded synthesized=N
```

If `attached_libs=` is dramatically lower than expected, see
"Troubleshooting" below.

### Verifying health from CLI

```bash
heimdall status                        # config + flow count
curl -s http://127.0.0.1:9999/api/health
curl -s http://127.0.0.1:9999/api/status | jq
```

### Reading flows

`heimdall flows list` accepts the same filters as the API:

```bash
heimdall flows list --limit 20
heimdall flows list --unit nginx.service
heimdall flows list --connection corp
heimdall flows list --host example.com
heimdall flows show 1234
```

### Watching live plaintext

Web UI at `http://<host>:9999/` (or `http://127.0.0.1:9999/` from the host itself).

- **Flows** tab — table of TCP flows with filters. Click a flow to
  open the side drawer; the **Plaintext** tab there shows
  hex+ASCII dumps of the captured TLS payloads bound to that flow.
- **Live Tap** tab — every captured plaintext message in real time,
  filterable by `slice/unit` substring or `cgroup_id`.

## Troubleshooting

### "tap: Go TLS binaries discovered count=0"

The Go scanner needs `CAP_SYS_PTRACE` to readlink other UIDs'
`/proc/<pid>/exe`. Check the systemd unit:

```bash
ps -o pid,user,args -C heimdall
cat /proc/<pid>/status | grep ^CapBnd
nix shell nixpkgs#libcap -c capsh --decode=$(cat /proc/<pid>/status | grep CapBnd | awk '{print $2}')
```

Should include `cap_sys_ptrace`. The full cap set required by the
daemon is:

```
CAP_BPF              # load eBPF programs + maps
CAP_NET_ADMIN        # attach cgroup hooks, manage tc-style egress
CAP_SYS_ADMIN        # cgroup v2 attach, mount-ns ops
CAP_SYS_PTRACE       # readlink /proc/<pid>/exe (Go scanner)
CAP_DAC_OVERRIDE     # rmdir user-owned heimdall-cli-* cgroups (GC)
```

If the unit is managed by NixOS, edit the heimdall service module:

```nix
AmbientCapabilities = [
  "CAP_BPF" "CAP_NET_ADMIN" "CAP_SYS_ADMIN"
  "CAP_SYS_PTRACE" "CAP_DAC_OVERRIDE"
];
CapabilityBoundingSet = [
  "CAP_BPF" "CAP_NET_ADMIN" "CAP_SYS_ADMIN"
  "CAP_SYS_PTRACE" "CAP_DAC_OVERRIDE"
];
```

then rebuild + restart the unit.

### "tap: libssl uprobes attached path=..." but no messages

Check the per-cgroup policy:

```bash
# Find the cgroup_id for a specific unit (inode == cgroup_id in cgroup v2)
stat -c '%i %n' /sys/fs/cgroup/system.slice/nginx.service
```

Then look up that inode in `CGROUP_POLICY`:

```bash
nix shell nixpkgs#bpftools -c sudo bpftool map dump name CGROUP_POLICY \
  | grep "$(printf '%016x' INODE | sed 's/\(..\)/\1 /g' | tr -d '\n' | rev | sed 's/  */ /g')"
```

If value is `0x06` or `0x07`, observe is off. Check the matching
rule in `/etc/heimdall/heimdall.ncl` and confirm the unit's
identity:

```bash
systemctl show -p Slice,FragmentPath,ControlGroup nginx.service
```

To force-observe a specific unit, add or amend a `routing.rules`
entry with `observe = true` and either restart the unit or wait
≤5 s for the next reconcile.

### Messages exist but `flow_id = NULL`

Three causes, in priority order:

1. **Host process** firing the uprobe (e.g. a local resolver).
   Expected — `DEFAULT_POLICY` should drop these but doesn't always
   completely.
2. **Pre-existing connection** that wasn't seen by `bootstrap`.
   Check the bootstrap log line; if `synthesized=` was 0 or the
   unit's cgroup wasn't in the resolver cache at boot time, restart
   the daemon.
3. **Race window** for connections opened during startup. Tap
   events that arrive after both PolicyEngine reconcile and
   bootstrap will correlate.

The /api/messages endpoint and Live Tap UI both attribute the
message to the right unit via `cgroup_id → UnitResolver.resolve()`
even when flow_id is NULL, so the user-facing experience is fine.

### "policy: reconciled writes=N deletes=0 cgroups=K"

- `writes` should be 0 on most ticks once startup converged.
- `cgroups` should match the unit count under `runtime.cgroup`
  (default `system.slice`), roughly `systemctl list-units --type=service --state=running | wc -l`.
  If much lower, `UnitResolver` isn't seeing them — check
  `runtime.cgroup` config and that `/sys/fs/cgroup` is the cgroup
  v2 unified hierarchy.

### Restart hangs / takes >10s

Two long operations at startup:

1. **UnitResolver scan** of `/sys/fs/cgroup` — should finish in
   <100 ms even on busy hosts.
2. **Tap binary scan** of every `/proc/<pid>/exe`. Each Go binary
   triggers a `.gopclntab` walk; on a host with several stripped
   100–200 MB binaries (e.g. containerd, large server processes)
   this can take ~2 seconds.

Look for `tap: Go Read RET sites found` lines — they're paced by
the per-binary scan.

### Bypass flow rows out of control

If `flows` table is growing fast with `connection_name='bypass'`,
some unit is opening many short-lived connections you don't
actually want to record. Add a rule:

```nickel
{ name = "chatty-noise",
  match = { units = [ "noisy-collector.service" ] },
  use     = "default",
  observe = false,   # disables both tap events and bypass flow inserts
}
```

The `observe = false` path is gated in eBPF so the bypass event
itself never fires for those cgroups (no perf-buffer overhead).

### `heimdall run` — child process can't reach its target

Most failures fall into one of three buckets:

1. **DNS still goes to the host resolver.** Run with `--dns fake`
   (default for `cli.run.default.dns = "fake"`). Confirm the child
   actually entered the mount-ns shim:

   ```bash
   pid=<child pid>
   sudo cat /proc/$pid/mountinfo | grep -E '/etc/nsswitch.conf|/etc/resolv.conf|/var/run/nscd/socket'
   ```

   You should see three bind-mounts. If empty, `unshare(CLONE_NEWUSER)`
   probably failed — check `dmesg | tail` and
   `/proc/sys/user/max_user_namespaces` (must be > 0).

2. **Registration didn't reach the daemon.** `heimdall run` registers
   via `POST /api/cli/register`. Confirm the daemon saw it:

   ```bash
   sudo bpftool map dump name CGROUP_POLICY | tail
   journalctl -u heimdall --since "1 minute ago" | grep cli
   ```

3. **systemd-run --user --scope failed.** Without user-cgroup
   delegation, the child has no writable subtree under
   `/sys/fs/cgroup/user.slice/user-<UID>.slice/...`. Check:

   ```bash
   systemctl --user status
   ls -ld /sys/fs/cgroup/user.slice/user-$UID.slice/user@$UID.service/app.slice
   ```

   The `app.slice` directory must be writable by `$UID` (cgroup v2
   delegation). On distros where this is restricted, run
   `heimdall run` as root.

### Orphan-cgroup GC isn't reaping leaked dirs

The GC walks `/sys/fs/cgroup/user.slice` every 30s (depth ≤ 6),
matching directories named `heimdall-cli-*` whose
`cgroup.events: populated 0`. Common reasons it skips a candidate:

- **Still populated** — a child process is still alive in the cgroup.
  Check `cat <path>/cgroup.procs`.
- **Outside the search root** — `heimdall run` always nests under
  `user.slice`; if you mkdir'd a test cgroup elsewhere it won't be
  swept.
- **Missing `CAP_DAC_OVERRIDE`** — `rmdir` returns `EACCES` because
  the cgroup dir is user-owned. Symptom in journal:
  `gc: rmdir failed path=... err=Permission denied`. Fix by adding
  the cap (see "tap: Go TLS binaries discovered count=0" above).

To force a sweep without waiting 30s:

```bash
sudo systemctl restart heimdall   # GC runs once at startup, then every 30s
```

## Where things live

```
/etc/heimdall/heimdall.{ncl,toml,json,yaml}   config (auto-discovered)
/etc/heimdall/README.md                       schema reference (heimdall init)
/etc/heimdall/lib.ncl                         Nickel contracts (heimdall init)
/etc/heimdall/secrets/                        password files (0400 root:root)
/var/lib/heimdall/flows.db                    sqlite (flows + messages)
/var/lib/heimdall/                            state dir
/etc/systemd/system/heimdall.service          systemd unit
                                              (NixOS-rendered when on NixOS)
```

`heimdall init` writes `lib.ncl` and `README.md` on every run, but
preserves an existing `heimdall.ncl` unless `--force` is passed.
Refresh the schema docs without losing your live config by re-running
`heimdall init` (no `--force`).

Logs go to journalctl. There's no separate log file.

## Routing × observe combination matrix

Every unit gets two independent decisions: which connection to route
through (`use`) and whether to capture TLS plaintext (`observe`).
All four combinations are valid:

| Combination | When you'd use it | How to set |
|---|---|---|
| `use: <name>` + `observe: true` | App unit whose egress should go through a named upstream (corp VPN, etc.) **and** whose plaintext you want to capture | `routing.rules` entry with `use = "<name>"`, `observe = true` |
| `use: <name>` + `observe: false` | Same routing, plaintext suppressed (credentials in flight, regulatory) | `routing.rules` entry with `observe = false` |
| `use: system` + `observe: true` | Host-bound infrastructure whose TLS plaintext is still useful even though the relay must not see it | `routing.rules` entry with `use = "system"`, `observe = true` |
| `use: <name>` + `observe: false` (rule-based) | Host-internal infra (containerd, log shippers) — route normally but silence the noise | `routing.rules` entry with `observe = false` |
| `use: system` + `observe: false` | Don't touch the unit at all (e.g. local node-exporter) | a catch-all `host-infra` rule |

Use the API or sqlite to spot-check what's actually being captured:

```bash
curl -s 'http://127.0.0.1:9999/api/messages?limit=200' \
  | jq -r '.[] | "\(.slice // "?")/\(.unit // "?") dir=\(.dir) cap=\(.captured_len)"' \
  | sort | uniq -c | sort -rn | head
```
