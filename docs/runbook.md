# Runbook

## Daily ops

### Building a new daemon

```bash
cd ~/heimdall

# eBPF first (its build artifact is include_bytes!'d into the daemon)
( cd heimdall-ebpf && cargo +nightly build --release )

# UI (only when components/ or hooks/ changed)
( cd heimdall-ui && bun run typecheck && bun run build )

# Daemon (embeds the UI bundle via rust-embed)
cargo build --release
```

### Deploying

```bash
sudo install -m 0755 target/release/heimdall /usr/local/bin/heimdall
sudo systemctl restart heimdall
sudo journalctl -u heimdall -f       # tail logs
```

A clean restart should print, in order:

```
config loaded
all connections resolved
flow store ready
pod informer started
fake-IP DNS server ready
HTTP API listening
pod informer initial sync complete pods=N
relay IP written to BPF map
eBPF connect4 attached
eBPF skb_egress attached
policy engine started
policy: reconciled writes=N deletes=0 pods=M cgroups=K
bypass: synthetic flow consumer started cpus=20
tap: libssl candidates discovered count=A
tap: Go TLS binaries discovered count=B
tap: libssl uprobes attached path=...   (×A)
tap: Go Read RET sites found ret_sites=7   (×B)
tap: go_tls_write attached path=...   (×B)
tap: started (Phase B) attached_libs=A+B persist=true
tap: store writer started
heimdall ready listen=0.0.0.0:12345
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

Should include `cap_sys_ptrace`. If missing, edit
`/etc/<host-config>/services/k0s/default.nix`:

```nix
AmbientCapabilities    = [ "CAP_BPF" "CAP_NET_ADMIN" "CAP_SYS_ADMIN" "CAP_SYS_PTRACE" ];
CapabilityBoundingSet  = [ "CAP_BPF" "CAP_NET_ADMIN" "CAP_SYS_ADMIN" "CAP_SYS_PTRACE" ];
```

then `sudo nixos-rebuild switch && sudo systemctl restart heimdall`.

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

## Where things live

```
/etc/heimdall/config.yaml             config
/etc/heimdall/secrets/                password files (mode 0400 root:root)
/etc/heimdall/config.yaml.bak.*       backups left by manual edits
/var/lib/heimdall/flows.db            sqlite (flows + messages tables)
/var/lib/heimdall/                    state dir (more files in future)
/usr/local/bin/heimdall               deployed binary
/etc/systemd/system/heimdall.service  ← actually a NixOS-rendered unit
/etc/<host-config>/services/k0s/default.nix   the unit's source of truth
~/heimdall/                      source repo
~/heimdall/docs/                 you are here
```

Logs go to journalctl. There's no separate log file.

## Cluster cases reference

What's running on this k0s node and which path each pod takes
through heimdall. Update when adding / removing workloads.

### Silenced (`observe: false`, `use: system` or `default`)

| Namespace | Pod | Rule | Why |
|---|---|---|---|
| kube-system | cilium-* (3) | cluster-infra | CNI plumbing |
| kube-system | coredns | cluster-infra | DNS |
| kube-system | kube-router | cluster-infra | service routing |
| kube-system | metrics-server | cluster-infra | kubelet metrics |
| local-path-storage | local-path-provisioner | cluster-infra | PVC provisioner |
| cattle-capi-system | capi-controller-manager | cattle-controllers | leader-election leases |
| cattle-turtles-system | rancher-turtles-controller-manager | cattle-controllers | leader-election leases |
| cattle-fleet-system | fleet-controller | fleet-controller | leader-election |
| cattle-system | rancher-webhook | rancher-webhook | admission only |
| cert-manager | cert-manager-webhook | cert-manager-noisy | admission only |
| cert-manager | cert-manager-cainjector | cert-manager-noisy | CA bundle injection |
| opik | opik-mysql-0 | data-stores | DB protocol |
| opik | opik-redis-master-0 | data-stores | DB protocol |
| opik | opik-minio | data-stores | object store |
| opik | opik-zookeeper-0 | data-stores | coordination |

### Observed (`observe: true`, `use: default`)

| Namespace | Pod | What's interesting |
|---|---|---|
| cattle-system | rancher | external catalog APIs, hub, user webhooks |
| cattle-fleet-local-system | fleet-agent | git clones |
| cattle-fleet-system | gitjob | git clones |
| cattle-fleet-system | helmops | helm chart fetches |
| cert-manager | cert-manager (leaf) | ACME → Let's Encrypt |
| ingress-nginx | ingress-nginx-controller | tls-terminating gateway |
| opik | opik-backend / python-backend / frontend | application API traffic |
| opik | chi-opik-clickhouse-cluster-0-0-0 | ClickHouse server |
| opik | opik-altinity-clickhouse-operator | operator API calls |

Use the API or sqlite to spot-check what's actually being captured:

```bash
curl -s 'http://127.0.0.1:9999/api/messages?limit=200' \
  | jq -r '.[] | "\(.pod_namespace)/\(.pod_name) dir=\(.dir) cap=\(.captured_len)"' \
  | sort | uniq -c | sort -rn | head
```
