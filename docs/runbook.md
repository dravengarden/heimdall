# Runbook

## Daily ops

### Building a new daemon

```bash
# eBPF first (its build artifact is include_bytes!'d into the daemon).
# Needs nightly + bpfel-unknown-none + rust-src + build-std.
( cd heimdall-ebpf && cargo +nightly build -Z build-std=core \
                                          --target bpfel-unknown-none --release )

# UI (only when components/ or hooks/ changed)
( cd heimdall-ui && bun install --frozen-lockfile && bun run typecheck && bun run build )

# Daemon (embeds the UI bundle via rust-embed)
cargo build --release
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
pod informer started
fake-IP DNS server ready
HTTP API listening
pod informer initial sync complete pods=N
relay IP written to BPF map
relay IPv6 written to BPF map
DNS hijack target written to BPF maps   ← DNS_ADDR_V4 + DNS_ADDR_V6 + DNS_PORT_V6
eBPF connect4 attached cgroup=...
eBPF connect4 attached (extra) cgroup=/sys/fs/cgroup/user.slice
eBPF connect6 attached cgroup=...
eBPF connect6 attached (extra) cgroup=/sys/fs/cgroup/user.slice
eBPF sendmsg attached prog=udp4_sendmsg
eBPF sendmsg attached prog=udp6_sendmsg
eBPF skb_egress attached cgroup=...
eBPF skb_egress attached (extra) cgroup=/sys/fs/cgroup/user.slice
policy engine started
orphan-cgroup GC spawned (interval 30s)
policy: reconciled writes=N deletes=0 pods=M cgroups=K
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
heimdall flows list --pod rancher
heimdall flows list --connection corp
heimdall flows list --host kong-hf
heimdall flows show 1234
```

### Watching live plaintext

Web UI at `http://localhost:9999/` (or `127.0.0.1:9999` from the host).

- **Flows** tab — table of TCP flows with filters. Click a flow to
  open the side drawer; the **Plaintext** tab there shows
  hex+ASCII dumps of the captured TLS payloads bound to that flow.
- **Live Tap** tab — every captured plaintext message in real time,
  filterable by `namespace/pod` substring or `cgroup_id`.

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
# Find the cgroup_id for a specific pod
uid=$(kubectl get pod -n NS POD -o jsonpath='{.metadata.uid}')
find /sys/fs/cgroup/kubepods -path "*pod${uid}*" -type d \
  | xargs -I{} stat -c "%i %n" {}
```

Then look up that inode in `CGROUP_POLICY`:

```bash
nix shell nixpkgs#bpftools -c sudo bpftool map dump name CGROUP_POLICY \
  | grep "$(printf '%016x' INODE | sed 's/\(..\)/\1 /g' | tr -d '\n' | rev | sed 's/  */ /g')"
```

If value is `0x06` or `0x07`, observe is off. Check the matching
rule in `/etc/heimdall/config.yaml` and the pod's labels:

```bash
kubectl get pod -n NS POD -o jsonpath='{.metadata.labels}'
kubectl get pod -n NS POD -o jsonpath='{.metadata.annotations}'
```

To force-observe a specific pod:

```bash
kubectl annotate pod -n NS POD heimdall.io/observe=true
```

The PolicyEngine reconciles within 5 seconds of the annotation
change.

### Messages exist but `flow_id = NULL`

Three causes, in priority order:

1. **Host process** firing the uprobe (e.g. dnscrypt-proxy). Expected
   — `DEFAULT_POLICY` should drop these but doesn't always
   completely.
2. **Pre-existing connection** that wasn't seen by `bootstrap`.
   Check the bootstrap log line; if `synthesized=` was 0 or your
   pod isn't in the BPF map yet at boot time, restart the daemon.
3. **Race window** for connections opened during startup. New
   tap events that arrive after both PolicyEngine reconcile and
   bootstrap will correlate.

The /api/messages endpoint and Live Tap UI both attribute the
message to the right pod via `cgroup_id → informer.lookup(uid)`
even when flow_id is NULL, so the user-facing experience is fine.

### "policy: reconciled writes=N deletes=0 pods=M cgroups=K"

- `writes` should be 0 on most ticks once startup converged.
- `pods` should match `kubectl get pods -A --field-selector spec.nodeName=NODE | wc -l`.
- `cgroups` ≈ `pods × 3` (parent + container + pause). If much
  lower, CgroupResolver isn't seeing them — check
  `/sys/fs/cgroup/kubepods` mount and `runtime.cgroup` config.

### Restart hangs / takes >10s

Two long operations at startup:

1. **CgroupResolver scan** of `/sys/fs/cgroup/kubepods` — should
   finish in <100ms even on busy nodes.
2. **Tap binary scan** of every `/proc/<pid>/exe`. Each Go binary
   triggers a `.gopclntab` walk; on a node with stripped 200MB
   binaries (rancher, cilium-envoy) this can take ~2 seconds.

Look for `tap: Go Read RET sites found` lines — they're paced by
the per-binary scan.

### Bypass flow rows out of control

If `flows` table is growing fast with `connection_name='bypass'`,
some pod is opening many short-lived connections you don't actually
want to record. Add a rule:

```yaml
- name: chatty-pod
  match: { namespaces: [the-noisy-ns] }
  use: default
  observe: false   # disables both tap events and bypass flow inserts
```

The `observe: false` path is gated in eBPF so the bypass event
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

2. **Pod-style label/annotation didn't take.** `heimdall run` does
   NOT use pod labels — it registers via `POST /api/cli/register`.
   Confirm the daemon saw the registration:

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

## Cluster cases reference

Every pod on this k0s node, individually. Update when adding /
removing workloads (or run `kubectl get pods -A` and reconcile).

### Silenced — `observe: false`

| Namespace | Pod | `use` | Rule | Why |
|---|---|---|---|---|
| kube-system | cilium-8bwrt | `system` | cluster-infra | CNI agent |
| kube-system | cilium-envoy-75h66 | `system` | cluster-infra | Cilium-managed Envoy sidecar |
| kube-system | cilium-operator-746545f74c-4686b | `system` | cluster-infra | Cilium operator |
| kube-system | coredns-6f57946586-tsz6n | `system` | cluster-infra | DNS |
| kube-system | metrics-server-f69b6f4d7-pmgtl | `system` | cluster-infra | kubelet metrics scraper |
| local-path-storage | local-path-provisioner-7bd467b8d5-nzmps | `system` | cluster-infra | PVC provisioner |
| cattle-capi-system | capi-controller-manager-744bcd597f-x7n8s | `default` | cattle-controllers | leader-election leases |
| cattle-turtles-system | rancher-turtles-controller-manager-66bb8b45dc-xw5rf | `default` | cattle-controllers | leader-election leases |
| cattle-fleet-system | fleet-controller-85dcb74785-nfgdr | `default` | fleet-controller | leader-election leases |
| cattle-system | rancher-webhook-65db7656c8-jssq5 | `default` | rancher-webhook | admission webhook only |
| cert-manager | cert-manager-cainjector-5774787d46-hdmcn | `default` | cert-manager-noisy | CA bundle injection |
| cert-manager | cert-manager-webhook-689df64959-978j9 | `default` | cert-manager-noisy | admission webhook only |
| opik | opik-mysql-0 | `default` | data-stores | mysql wire protocol |
| opik | opik-redis-master-0 | `default` | data-stores | redis wire protocol |
| opik | opik-minio-5c9966fb6b-mwzv2 | `default` | data-stores | s3-compat object store |
| opik | opik-zookeeper-0 | `default` | data-stores | coordination |

### Observed — `observe: true`, `use: default` (the routing default)

| Namespace | Pod | Why we want plaintext | Tap source |
|---|---|---|---|
| cattle-system | rancher-698f96874d-tqv5r | catalog APIs, hub, user webhooks, watch streams | Go (stripped → `.gopclntab`) |
| cattle-fleet-local-system | fleet-agent-849974b847-7ttkl | GitOps reconcile, git clones | Go (stripped) |
| cattle-fleet-system | gitjob-7c7447b4cb-jqccb | git clones | Go (stripped) |
| cattle-fleet-system | helmops-7c4cf5bdd7-cmg48 | helm chart fetches | Go (stripped) |
| cert-manager | cert-manager-6b6bf64d6c-59k88 | ACME → Let's Encrypt requests | Go (`manager` binary, has symbols) |
| ingress-nginx | ingress-nginx-controller-6cc8797689-wkxm7 | tls-terminating gateway requests | libssl |
| opik | opik-backend-64d7947f57-xq7fh | Java application API | Java — *currently no plaintext capture* |
| opik | opik-python-backend-847f77fbd4-kbs4t | Python application | libssl |
| opik | opik-frontend-8467675f55-dscrb | Node.js frontend API | libssl (Node) |
| opik | chi-opik-clickhouse-cluster-0-0-0 | ClickHouse SQL traffic | libssl |
| opik | opik-altinity-clickhouse-operator-856f68b7b4-zlfjg | operator's k8s API calls | Go |

### Other / transient

| Namespace | Pod | Status | Treatment |
|---|---|---|---|
| fleet-default | rke2-machineconfig-cleanup-cronjob-… | `Completed` (CronJob, runs once daily) | Falls into `routing.default` if running. Each new run gets `observe: true`; the run is too short-lived to matter for noise. |

### Cases NOT currently exercised

These are supported by the schema but no pod on this cluster
matches them. Documented here so they're discoverable:

| Combination | When you'd use it | How to set |
|---|---|---|
| `use: corp` + `observe: true` | Debug pod that needs to reach Corp-internal hosts via the Mac SOCKS5, with plaintext capture | annotate pod: `heimdall.io/connection: corp` |
| `use: corp` + `observe: false` | Same routing, but suppress plaintext (e.g. running personal credentials through it) | both annotations |
| `use: system` + `observe: true` | Pod that should not be redirected (e.g. uses host network or is otherwise architecturally outside the relay) but you still want to see its TLS plaintext | both annotations: `connection: system`, `observe: true` |
| `use: default` + `observe: false` | Default route through v2raya but silenced — used today by the cattle-controllers / data-stores rules | rule with `observe: false` |

Use the API or sqlite to spot-check what's actually being captured:

```bash
curl -s 'http://127.0.0.1:9999/api/messages?limit=200' \
  | jq -r '.[] | "\(.pod_namespace)/\(.pod_name) dir=\(.dir) cap=\(.captured_len)"' \
  | sort | uniq -c | sort -rn | head
```
